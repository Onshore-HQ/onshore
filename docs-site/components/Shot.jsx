/** A console screenshot, framed like a browser window. Highlights are drawn into the image itself. */
export function Shot({ src, alt, caption, width }) {
  return (
    <figure className="rv-shot" style={width ? { maxWidth: width } : undefined}>
      <div className="rv-shot-frame">
        <div className="rv-shot-bar" aria-hidden><i /><i /><i /></div>
        <a href={src} target="_blank" rel="noreferrer" title="Open full size">
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img src={src} alt={alt} loading="lazy" />
        </a>
      </div>
      {caption && <figcaption>{caption}</figcaption>}
    </figure>
  );
}
