/** A grid of links to other pages. */
export function Cards({ items }) {
  return (
    <div className="rv-cards">
      {items.map(([title, href, text]) => (
        <a key={href} className="rv-card" href={href}><b>{title}</b><span>{text}</span></a>
      ))}
    </div>
  );
}
export const Ent = () => <span className="rv-pill ent">Enterprise · Cloud</span>;
export const Early = () => <span className="rv-pill early">Early access</span>;
