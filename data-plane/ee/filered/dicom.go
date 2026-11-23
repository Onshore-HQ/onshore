package filered

// DICOM medical images. Two kinds of identifiers live in a DICOM file: the header
// (patient name, IDs, dates, institution, the people involved) and text burned into
// the pixels by the scanner or a workstation. Both are removed:
//
//   - The header follows the DICOM Basic Application Level Confidentiality Profile
//     (PS3.15 Annex E) for the attributes listed below: identifying ones are emptied
//     or removed, private tags are dropped, UIDs are replaced consistently, and every
//     remaining text attribute goes through detection.
//   - Each frame is rendered, read with OCR and painted over where it shows an
//     identifier, including the patient's own header values, which catches names in
//     formats detection wouldn't recognise on its own.
//
// Compressed pixel data is first decompressed with DCMTK. A transfer syntax it can't
// decode is refused, never passed through.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/suyashkumar/dicom"
	"github.com/suyashkumar/dicom/pkg/frame"
	"github.com/suyashkumar/dicom/pkg/tag"
)

// MaxFrames bounds OCR work on one file: cine loops can hold thousands of frames.
const MaxFrames = 500

// isDICOM reports the "DICM" marker after the 128-byte preamble.
func isDICOM(b []byte) bool { return len(b) > 132 && string(b[128:132]) == "DICM" }

// emptied attributes are kept but given no value, as the profile's "Z" action does;
// removed ones go entirely ("X"). Identifying values from both are also looked for in
// the pixels.
var (
	emptied = []tag.Tag{
		tag.PatientName, tag.PatientID, tag.PatientBirthDate, tag.PatientSex,
		tag.AccessionNumber, tag.ReferringPhysicianName, tag.StudyID,
		tag.StudyDate, tag.StudyTime, tag.ContentCreatorName,
	}
	removed = []tag.Tag{
		tag.OtherPatientIDs, tag.OtherPatientNames, tag.OtherPatientIDsSequence,
		tag.PatientBirthName, tag.PatientMotherBirthName, tag.PatientAddress,
		tag.PatientTelephoneNumbers, tag.PatientBirthTime, tag.PatientAge,
		tag.PatientSize, tag.PatientWeight, tag.MedicalRecordLocator,
		tag.EthnicGroup, tag.Occupation, tag.MilitaryRank, tag.BranchOfService,
		tag.PatientReligiousPreference, tag.PatientComments, tag.AdditionalPatientHistory,
		tag.CountryOfResidence, tag.RegionOfResidence, tag.InsurancePlanIdentification,
		tag.InstitutionName, tag.InstitutionAddress, tag.InstitutionalDepartmentName,
		tag.ReferringPhysicianAddress, tag.ReferringPhysicianTelephoneNumbers,
		tag.PhysiciansOfRecord, tag.PerformingPhysicianName, tag.NameOfPhysiciansReadingStudy,
		tag.OperatorsName, tag.RequestingPhysician, tag.ScheduledPerformingPhysicianName,
		tag.StationName, tag.DeviceSerialNumber, tag.RequestAttributesSequence,
		tag.AdmissionID, tag.IssuerOfPatientID, tag.StudyDescription,
		tag.SeriesDate, tag.AcquisitionDate, tag.ContentDate,
		tag.SeriesTime, tag.AcquisitionTime, tag.ContentTime, tag.AcquisitionDateTime,
		tag.PerformedProcedureStepStartDate, tag.PerformedProcedureStepStartTime,
		tag.PerformedProcedureStepID, tag.PerformedProcedureStepDescription,
		tag.ImageComments, tag.FrameComments, tag.DerivationDescription,
	}
	// keptUIDs identify a type, not a patient or study, so they stay as they are.
	keptUIDs = map[tag.Tag]bool{
		tag.TransferSyntaxUID: true, tag.SOPClassUID: true, tag.MediaStorageSOPClassUID: true,
		tag.ImplementationClassUID: true, tag.ReferencedSOPClassUID: true,
	}
	textVRs = map[string]bool{"LO": true, "SH": true, "ST": true, "LT": true, "UT": true, "PN": true, "UC": true}
)

// decompressors turn compressed transfer syntaxes into explicit VR little endian.
var decompressors = map[string]string{
	"1.2.840.10008.1.2.4.50": "dcmdjpeg", "1.2.840.10008.1.2.4.51": "dcmdjpeg",
	"1.2.840.10008.1.2.4.57": "dcmdjpeg", "1.2.840.10008.1.2.4.70": "dcmdjpeg",
	"1.2.840.10008.1.2.5":    "dcmdrle",
	"1.2.840.10008.1.2.4.80": "dcmdjpls", "1.2.840.10008.1.2.4.81": "dcmdjpls",
}

// errCompressed is refused: the pixels can't be decoded, so they can't be checked.
var errCompressed = fmt.Errorf("%w: compressed DICOM pixel data in a format that can't be decoded here", ErrUnsupported)

func (r *Redactor) dicom(ctx context.Context, dir string, body []byte) (*Result, error) {
	ds, err := dicom.Parse(bytes.NewReader(body), int64(len(body)), nil, dicom.AllowMissingMetaElementGroupLength())
	if err != nil {
		return nil, errors.New("could not read the DICOM file")
	}
	if ts := stringValue(&ds, tag.TransferSyntaxUID); hasEncapsulatedPixels(&ds) {
		tool, ok := decompressors[ts]
		if !ok {
			return nil, errCompressed
		}
		in, out := filepath.Join(dir, "in.dcm"), filepath.Join(dir, "plain.dcm")
		if err := os.WriteFile(in, body, 0o600); err != nil {
			return nil, err
		}
		// Colour comes out pixel by pixel, the layout paintSamples writes.
		if _, err := r.run(ctx, tool, "+px", in, out); err != nil {
			return nil, errCompressed
		}
		plain, err := os.ReadFile(out) // #nosec generated path
		if err != nil {
			return nil, err
		}
		if ds, err = dicom.Parse(bytes.NewReader(plain), int64(len(plain)), nil, dicom.AllowMissingMetaElementGroupLength()); err != nil || hasEncapsulatedPixels(&ds) {
			return nil, errCompressed
		}
	}

	if pc, err := ds.FindElementByTag(tag.PlanarConfiguration); err == nil {
		if v, ok := pc.Value.GetValue().([]int); ok && len(v) > 0 && v[0] == 1 {
			return nil, fmt.Errorf("%w: colour stored plane by plane", ErrUnsupported)
		}
	}
	counts := map[string]int{}
	terms := identifyingTerms(&ds)
	// MONOCHROME1 shows low values as white, so a box there is painted at the top value.
	inverted := strings.HasPrefix(strings.ToUpper(stringValue(&ds, tag.PhotometricInterpretation)), "MONOCHROME1")
	r.cleanHeader(&ds, counts)

	low := false
	if px, err := ds.FindElementByTag(tag.PixelData); err == nil {
		info, ok := px.Value.GetValue().(dicom.PixelDataInfo)
		if !ok {
			return nil, errors.New("could not read the DICOM pixels")
		}
		if len(info.Frames) > MaxFrames {
			return nil, fmt.Errorf("%w: more than %d frames", ErrUnsupported, MaxFrames)
		}
		for i, f := range info.Frames {
			nf, err := f.GetNativeFrame()
			if err != nil {
				return nil, errCompressed
			}
			lowFrame, err := r.redactFrame(ctx, dir, i, nf, inverted, terms, counts)
			if err != nil {
				return nil, err
			}
			low = low || lowFrame
		}
		if !low {
			setString(&ds, tag.BurnedInAnnotation, "CS", "NO")
		}
	}
	setString(&ds, tag.PatientIdentityRemoved, "CS", "YES")
	setString(&ds, tag.DeidentificationMethod, "LO", "Onshore file redactor: basic profile and burned-in text")

	var buf bytes.Buffer
	if err := dicom.Write(&buf, ds, dicom.SkipVRVerification(), dicom.SkipValueTypeVerification(), dicom.DefaultMissingTransferSyntax()); err != nil {
		return nil, errors.New("could not write the DICOM file")
	}
	return &Result{Body: buf.Bytes(), ContentType: "application/dicom", Counts: counts, LowConfidence: low}, nil
}

func hasEncapsulatedPixels(ds *dicom.Dataset) bool {
	px, err := ds.FindElementByTag(tag.PixelData)
	if err != nil {
		return false
	}
	info, ok := px.Value.GetValue().(dicom.PixelDataInfo)
	return ok && info.IsEncapsulated
}

func stringValue(ds *dicom.Dataset, t tag.Tag) string {
	e, err := ds.FindElementByTag(t)
	if err != nil {
		return ""
	}
	if v, ok := e.Value.GetValue().([]string); ok && len(v) > 0 {
		return strings.TrimRight(v[0], " \x00")
	}
	return ""
}

// identifyingTerms collects the words of identifying header values, to find them in
// the pixels: "DOE^JANE" gives "doe" and "jane", and an ID gives itself.
func identifyingTerms(ds *dicom.Dataset) map[string]bool {
	terms := map[string]bool{}
	for _, t := range append(append([]tag.Tag{}, emptied...), removed...) {
		e, err := ds.FindElementByTagNested(t)
		if err != nil {
			continue
		}
		vals, ok := e.Value.GetValue().([]string)
		if !ok {
			continue
		}
		for _, v := range vals {
			for _, w := range strings.FieldsFunc(strings.ToLower(v), func(r rune) bool { return r == '^' || r == ' ' || r == ',' || r == '=' }) {
				// Short words such as "m" for sex or "dr" would paint over half the image.
				if len([]rune(w)) >= 3 {
					terms[w] = true
				}
			}
		}
	}
	return terms
}

// cleanHeader applies the profile in place, including inside sequences.
func (r *Redactor) cleanHeader(ds *dicom.Dataset, counts map[string]int) {
	drop := map[tag.Tag]bool{}
	for _, t := range removed {
		drop[t] = true
	}
	empty := map[tag.Tag]bool{}
	for _, t := range emptied {
		empty[t] = true
	}
	var walk func(elems []*dicom.Element) []*dicom.Element
	walk = func(elems []*dicom.Element) []*dicom.Element {
		kept := elems[:0]
		for _, e := range elems {
			switch {
			case tag.IsPrivate(e.Tag.Group) || drop[e.Tag]:
				counts["dicom_header"]++
				continue
			case empty[e.Tag]:
				if v, ok := e.Value.GetValue().([]string); ok && len(v) > 0 && strings.Trim(strings.Join(v, ""), " \x00") != "" {
					counts["dicom_header"]++
				}
				e.Value, _ = dicom.NewValue([]string{""})
			case e.RawValueRepresentation == "UI" && !keptUIDs[e.Tag]:
				if v, ok := e.Value.GetValue().([]string); ok {
					for i := range v {
						v[i] = r.newUID(strings.TrimRight(v[i], " \x00"))
					}
				}
			case textVRs[e.RawValueRepresentation]:
				if v, ok := e.Value.GetValue().([]string); ok {
					for i := range v {
						if active := r.scan(v[i], "", counts); len(active) > 0 {
							for _, a := range active {
								counts[string(a.Type)]++
							}
							v[i] = ""
						}
					}
				}
			case e.Value.ValueType() == dicom.Sequences:
				if items, ok := e.Value.GetValue().([]*dicom.SequenceItemValue); ok {
					rebuilt := make([][]*dicom.Element, 0, len(items))
					for _, it := range items {
						if inner, ok := it.GetValue().([]*dicom.Element); ok {
							rebuilt = append(rebuilt, walk(append([]*dicom.Element{}, inner...)))
						}
					}
					if nv, err := dicom.NewValue(rebuilt); err == nil {
						e.Value = nv
					}
				}
			}
			kept = append(kept, e)
		}
		return kept
	}
	ds.Elements = walk(ds.Elements)
}

// newUID replaces a UID with one derived from it under the install's key, so files of
// one study still share a study UID after redaction, and the original can't be guessed.
func (r *Redactor) newUID(old string) string {
	if old == "" {
		return ""
	}
	m := hmac.New(sha256.New, r.uidKey())
	m.Write([]byte(old))
	n := new(big.Int).SetBytes(m.Sum(nil)[:16])
	return "2.25." + n.String()
}

func (r *Redactor) uidKey() []byte {
	if r.UIDKey != nil {
		return r.UIDKey
	}
	return []byte("onshore-dicom-uid")
}

func setString(ds *dicom.Dataset, t tag.Tag, vr, value string) {
	if e, err := ds.FindElementByTag(t); err == nil {
		e.Value, _ = dicom.NewValue([]string{value})
		return
	}
	e, err := dicom.NewElement(t, []string{value})
	if err != nil {
		return
	}
	e.RawValueRepresentation = vr
	// Keep the dataset in tag order, as the format requires.
	i := 0
	for i < len(ds.Elements) && ds.Elements[i].Tag.Compare(t) < 0 {
		i++
	}
	ds.Elements = append(ds.Elements, nil)
	copy(ds.Elements[i+1:], ds.Elements[i:])
	ds.Elements[i] = e
}

// redactFrame renders one frame for OCR, finds what to cover, and paints it into the
// frame's own samples, so the written file carries the covered pixels.
func (r *Redactor) redactFrame(ctx context.Context, dir string, n int, nf frame.INativeFrame, inverted bool, terms map[string]bool, counts map[string]int) (bool, error) {
	img, lo, hi := render(nf)
	if img == nil {
		return false, fmt.Errorf("%w: unsupported DICOM pixel layout", ErrUnsupported)
	}
	path := filepath.Join(dir, fmt.Sprintf("frame%d.png", n))
	f, err := os.Create(path) // #nosec generated path
	if err != nil {
		return false, err
	}
	err = png.Encode(f, img)
	f.Close()
	if err != nil {
		return false, err
	}
	words, err := r.readWords(ctx, path)
	if err != nil {
		return false, err
	}
	boxes := r.boxes(words, counts)
	for _, w := range words {
		if terms[strings.Trim(strings.ToLower(w.text), ".,:;()[]^")] {
			counts["dicom_pixel_header_value"]++
			boxes = append(boxes, image.Rect(w.left-3, w.top-3, w.left+w.w+3, w.top+w.h+3))
		}
	}
	fill := lo
	if inverted {
		fill = hi
	}
	paintSamples(nf, boxes, fill)
	// No words at all is normal for a scan without annotations, so only words read
	// with low confidence make a frame uncertain.
	return len(words) > 0 && lowConfidence(words), nil
}

// render scales a frame's samples to 8 bits, so faint annotations stay readable.
func render(nf frame.INativeFrame) (image.Image, int, int) {
	rows, cols, spp := nf.Rows(), nf.Cols(), nf.SamplesPerPixel()
	if rows == 0 || cols == 0 || (spp != 1 && spp != 3) {
		return nil, 0, 0
	}
	sample := func(x, y, s int) int {
		px, err := nf.GetPixel(x, y)
		if err != nil || s >= len(px) {
			return 0
		}
		return px[s]
	}
	lo, hi := sample(0, 0, 0), sample(0, 0, 0)
	for y := 0; y < rows; y++ {
		for x := 0; x < cols; x++ {
			for s := 0; s < spp; s++ {
				v := sample(x, y, s)
				lo, hi = min(lo, v), max(hi, v)
			}
		}
	}
	span := hi - lo
	if span == 0 {
		span = 1
	}
	scale := func(v int) uint8 { return uint8((v - lo) * 255 / span) }
	if spp == 1 {
		g := image.NewGray(image.Rect(0, 0, cols, rows))
		for y := 0; y < rows; y++ {
			for x := 0; x < cols; x++ {
				g.SetGray(x, y, color.Gray{Y: scale(sample(x, y, 0))})
			}
		}
		return g, lo, hi
	}
	c := image.NewRGBA(image.Rect(0, 0, cols, rows))
	for y := 0; y < rows; y++ {
		for x := 0; x < cols; x++ {
			c.SetRGBA(x, y, color.RGBA{scale(sample(x, y, 0)), scale(sample(x, y, 1)), scale(sample(x, y, 2)), 255})
		}
	}
	return c, lo, hi
}

// paintSamples sets every sample inside the boxes to fill.
func paintSamples(nf frame.INativeFrame, boxes []image.Rectangle, fill int) {
	rows, cols, spp := nf.Rows(), nf.Cols(), nf.SamplesPerPixel()
	bounds := image.Rect(0, 0, cols, rows)
	set := func(i int) {}
	switch d := nf.RawDataSlice().(type) {
	case []uint8:
		set = func(i int) { d[i] = uint8(fill) }
	case []uint16:
		set = func(i int) { d[i] = uint16(fill) }
	case []uint32:
		set = func(i int) { d[i] = uint32(fill) }
	case []int8:
		set = func(i int) { d[i] = int8(fill) }
	case []int16:
		set = func(i int) { d[i] = int16(fill) }
	case []int32:
		set = func(i int) { d[i] = int32(fill) }
	}
	for _, b := range boxes {
		b = b.Intersect(bounds)
		for y := b.Min.Y; y < b.Max.Y; y++ {
			for x := b.Min.X; x < b.Max.X; x++ {
				for s := 0; s < spp; s++ {
					set((y*cols+x)*spp + s)
				}
			}
		}
	}
}
