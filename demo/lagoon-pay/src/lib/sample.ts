// Fresh made-up details for the sign-up form, so that nobody types a real BVN during a demo.
const pick = <T,>(a: T[]) => a[Math.floor(Math.random() * a.length)]!;
const digits = (n: number) => Array.from({ length: n }, () => Math.floor(Math.random() * 10)).join("");
export function sampleCustomer() {
  const f = pick(["Adaeze", "Tunde", "Aisha", "Efe", "Kemi", "Musa"]), l = pick(["Okafor", "Bakare", "Yusuf", "Ibekwe", "Lawal"]);
  return { fullName: `${f} ${l}`, phone: `+234803${digits(7)}`, email: `${f}.${l}@example.ng`.toLowerCase(), dob: "1994-05-17", bvn: `22${digits(9)}` };
}
export function nuban(code: string) {
  const serial = digits(9), s = code.padStart(6, "0") + serial, w = [3, 7, 3, 3, 7, 3, 3, 7, 3, 3, 7, 3, 3, 7, 3];
  const sum = [...s].reduce((t, d, i) => t + Number(d) * w[i]!, 0);
  return serial + String((10 - (sum % 10)) % 10);
}
