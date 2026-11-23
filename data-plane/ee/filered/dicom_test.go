package filered

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/suyashkumar/dicom"
	"github.com/suyashkumar/dicom/pkg/frame"
	"github.com/suyashkumar/dicom/pkg/tag"

	"onshore/data-plane/internal/detect"
)

// testScan builds a 32x32 16-bit scan whose header names a patient and whose pixels
// carry a bright annotation block where the OCR stub says "JANE" is written.
func testScan(t *testing.T) []byte {
	t.Helper()
	el := func(tg tag.Tag, v any) *dicom.Element {
		e, err := dicom.NewElement(tg, v)
		if err != nil {
			t.Fatalf("element %v: %v", tg, err)
		}
		return e
	}
	nf := frame.NewNativeFrame[uint16](16, 32, 32, 32*32, 1)
	for i := range nf.RawData {
		nf.RawData[i] = 100
	}
	for y := 2; y < 6; y++ {
		for x := 2; x < 12; x++ {
			nf.RawData[y*32+x] = 4000
		}
	}
	private, _ := dicom.NewValue([]string{"SCANNER SECRET"})
	ds := dicom.Dataset{Elements: []*dicom.Element{
		el(tag.MediaStorageSOPClassUID, []string{"1.2.840.10008.5.1.4.1.1.7"}),
		el(tag.MediaStorageSOPInstanceUID, []string{"1.2.3.4.5.6.7"}),
		el(tag.TransferSyntaxUID, []string{"1.2.840.10008.1.2.1"}),
		el(tag.SOPClassUID, []string{"1.2.840.10008.5.1.4.1.1.7"}),
		el(tag.SOPInstanceUID, []string{"1.2.3.4.5.6.7"}),
		el(tag.InstitutionName, []string{"St Mary Hospital"}),
		{Tag: tag.Tag{Group: 0x0009, Element: 0x0010}, RawValueRepresentation: "LO", ValueRepresentation: tag.VRString, Value: private},
		el(tag.PatientName, []string{"DOE^JANE"}),
		el(tag.PatientID, []string{"MRN-884213"}),
		el(tag.PatientBirthDate, []string{"19800101"}),
		el(tag.StudyInstanceUID, []string{"1.2.3.4.100"}),
		el(tag.SeriesDescription, []string{"Follow-up for jane.doe@example.com"}),
		el(tag.SamplesPerPixel, []int{1}),
		el(tag.PhotometricInterpretation, []string{"MONOCHROME2"}),
		el(tag.Rows, []int{32}),
		el(tag.Columns, []int{32}),
		el(tag.BitsAllocated, []int{16}),
		el(tag.BitsStored, []int{16}),
		el(tag.HighBit, []int{15}),
		el(tag.PixelRepresentation, []int{0}),
		el(tag.PixelData, dicom.PixelDataInfo{Frames: []*frame.Frame{{NativeData: nf}}}),
	}}
	var buf bytes.Buffer
	if err := dicom.Write(&buf, ds); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func dicomRedactor() *Redactor {
	return &Redactor{
		Engine: detect.New(detect.Config{}),
		TmpDir: "",
		UIDKey: []byte("test key"),
		ocrFn: func(context.Context, string) ([]word, error) {
			return []word{{left: 2, top: 2, w: 10, h: 4, line: 1, conf: 95, text: "JANE"}, {left: 20, top: 20, w: 8, h: 4, line: 2, conf: 95, text: "AP"}}, nil
		},
	}
}

func TestDICOMHeaderAndPixelsAreCleaned(t *testing.T) {
	in := testScan(t)
	if sniff(in) != "dicom" {
		t.Fatalf("sniff = %q", sniff(in))
	}
	res, err := dicomRedactor().Redact(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if res.ContentType != "application/dicom" {
		t.Fatalf("content type %q", res.ContentType)
	}
	out, err := dicom.Parse(bytes.NewReader(res.Body), int64(len(res.Body)), nil)
	if err != nil {
		t.Fatalf("output is not valid DICOM: %v", err)
	}
	for _, s := range []string{"DOE", "JANE", "MRN-884213", "19800101", "St Mary", "SCANNER SECRET", "jane.doe@example.com", "1.2.3.4.100", "1.2.3.4.5.6.7"} {
		if bytes.Contains(res.Body, []byte(s)) {
			t.Errorf("output still holds %q", s)
		}
	}
	if v := stringValue(&out, tag.PatientIdentityRemoved); v != "YES" {
		t.Errorf("PatientIdentityRemoved = %q", v)
	}
	if v := stringValue(&out, tag.SOPInstanceUID); v != stringValue(&out, tag.MediaStorageSOPInstanceUID) || v == "" {
		t.Errorf("instance UID %q doesn't match the file meta %q", v, stringValue(&out, tag.MediaStorageSOPInstanceUID))
	}
	px, err := out.FindElementByTag(tag.PixelData)
	if err != nil {
		t.Fatal(err)
	}
	nf, err := px.Value.GetValue().(dicom.PixelDataInfo).Frames[0].GetNativeFrame()
	if err != nil {
		t.Fatal(err)
	}
	data := nf.RawDataSlice().([]uint16)
	if data[3*32+5] != 100 {
		t.Errorf("the annotation pixel is %d, want the background 100", data[3*32+5])
	}
	if data[25*32+25] != 100 {
		t.Errorf("an untouched pixel changed to %d", data[25*32+25])
	}
	if res.Counts["dicom_pixel_header_value"] == 0 {
		t.Errorf("the patient's name in the pixels wasn't counted: %v", res.Counts)
	}
}

func TestDICOMStudyUIDIsStableAcrossFiles(t *testing.T) {
	r := dicomRedactor()
	a, err := r.Redact(context.Background(), testScan(t))
	if err != nil {
		t.Fatal(err)
	}
	b, err := r.Redact(context.Background(), testScan(t))
	if err != nil {
		t.Fatal(err)
	}
	ua, _ := dicom.Parse(bytes.NewReader(a.Body), int64(len(a.Body)), nil)
	ub, _ := dicom.Parse(bytes.NewReader(b.Body), int64(len(b.Body)), nil)
	if x, y := stringValue(&ua, tag.StudyInstanceUID), stringValue(&ub, tag.StudyInstanceUID); x != y || x == "" {
		t.Errorf("study UIDs differ: %q, %q", x, y)
	}
}

func TestCompressedDICOMWithoutDecoderIsRefused(t *testing.T) {
	el := func(tg tag.Tag, v any) *dicom.Element {
		e, err := dicom.NewElement(tg, v)
		if err != nil {
			t.Fatalf("element %v: %v", tg, err)
		}
		return e
	}
	// JPEG 2000: nothing in the container decodes it, so it can't be checked.
	ds := dicom.Dataset{Elements: []*dicom.Element{
		el(tag.MediaStorageSOPClassUID, []string{"1.2.840.10008.5.1.4.1.1.7"}),
		el(tag.MediaStorageSOPInstanceUID, []string{"1.2.3"}),
		el(tag.TransferSyntaxUID, []string{"1.2.840.10008.1.2.4.90"}),
		el(tag.PatientName, []string{"DOE^JANE"}),
		el(tag.Rows, []int{8}), el(tag.Columns, []int{8}),
		el(tag.BitsAllocated, []int{8}), el(tag.SamplesPerPixel, []int{1}),
		el(tag.PixelData, dicom.PixelDataInfo{IsEncapsulated: true, Frames: []*frame.Frame{{Encapsulated: true, EncapsulatedData: frame.EncapsulatedFrame{Data: []byte{0xff, 0x4f, 0xff, 0x51}}}}}),
	}}
	// The writer encodes encapsulated pixels only for an undefined length.
	ds.Elements[len(ds.Elements)-1].ValueLength = tag.VLUndefinedLength
	ds.Elements[len(ds.Elements)-1].RawValueRepresentation = "OB"
	var buf bytes.Buffer
	if err := dicom.Write(&buf, ds, dicom.SkipVRVerification()); err != nil {
		t.Fatal(err)
	}
	_, err := dicomRedactor().Redact(context.Background(), buf.Bytes())
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err = %v, want ErrUnsupported", err)
	}
}
