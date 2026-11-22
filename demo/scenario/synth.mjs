// Seeded synthetic data. Nothing here comes from a real dataset, and the seed is fixed so that
// every reset brings back the same people. Generated numbers can match real ones by chance:
// they are shown briefly on screen, never published as a list, and never used outside this demo.
export const SEED = 20270101;
export function rng(seed = SEED) { let a = seed >>> 0; return () => { a = (a + 0x6d2b79f5) >>> 0; let t = a; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }

const FIRST = ["Adaeze", "Chidi", "Ngozi", "Emeka", "Ifeoma", "Obinna", "Chiamaka", "Uche", "Tunde", "Funke", "Yetunde", "Segun", "Bisi", "Kemi", "Dele", "Tola", "Aisha", "Musa", "Fatima", "Sani", "Hauwa", "Ibrahim", "Zainab", "Bello", "Efe", "Ese", "Oghene", "Tamuno", "Ebi", "Boma", "Nsikak", "Ekaette"];
const LAST = ["Okafor", "Eze", "Nwosu", "Okonkwo", "Obi", "Anyanwu", "Adeyemi", "Bakare", "Ogunleye", "Afolabi", "Balogun", "Oyelaran", "Yusuf", "Abubakar", "Danjuma", "Garba", "Lawal", "Sule", "Oghenekaro", "Tamunotonye", "Ekpo", "Udoh", "Etim", "Ibekwe"];
const CITIES = ["Lagos", "Abuja", "Port Harcourt", "Kano", "Enugu", "Ibadan"];
const NETS = ["803", "806", "810", "813", "816", "703", "706", "802", "808", "812", "701", "805", "807", "815"];
const EMPLOYERS = ["Harbour Foods Ltd", "Bluewater Logistics", "Ikeja Print Works", "Sahel Agro Traders", "Marina Pharmacy", "Self-employed"];
// Fictional banks with made-up 3-digit codes, chosen so that none is in the real institution list.
export const BANKS = [{ code: "811", name: "Harbour Trust Bank" }, { code: "822", name: "Kingsway Mutual Bank" }, { code: "833", name: "Savanna Heritage Bank" }, { code: "844", name: "Delta Crest Bank" }, { code: "855", name: "Northgate Community Bank" }, { code: "866", name: "Lekki Union Bank" }];

const digits = (r, n) => Array.from({ length: n }, () => Math.floor(r() * 10)).join("");
const pick = (r, a) => a[Math.floor(r() * a.length)];

/** CBN NUBAN check digit: weights 3,7,3 over the padded code and serial; 10 minus the sum mod 10. */
export function nuban(code, serial) {
  const s = code.padStart(6, "0") + serial;
  const w = [3, 7, 3, 3, 7, 3, 3, 7, 3, 3, 7, 3, 3, 7, 3];
  const sum = [...s].reduce((t, d, i) => t + Number(d) * w[i], 0);
  return serial + String((10 - sum % 10) % 10);
}

export function customer(i) {
  const r = rng(SEED + i * 7919);
  const first = pick(r, FIRST), last = pick(r, LAST);
  const bank = pick(r, BANKS);
  const age = 19 + Math.floor(r() * 42);
  return {
    ref: `LGN-C-${String(i).padStart(5, "0")}`,
    fullName: `${first} ${last}`,
    phone: `+234${pick(r, NETS)}${digits(r, 7)}`,
    email: `${first}.${last}${i}@example.ng`.toLowerCase(),
    dob: `${2026 - age}-${String(1 + Math.floor(r() * 12)).padStart(2, "0")}-${String(1 + Math.floor(r() * 28)).padStart(2, "0")}`,
    city: pick(r, CITIES),
    bvn: `22${digits(r, 9)}`,
    nin: `7${digits(r, 10)}`,
    bank: bank.name,
    bankCode: bank.code,
    nuban: nuban(bank.code, digits(r, 9)),
    employer: pick(r, EMPLOYERS),
    income: 80000 + Math.floor(r() * 900) * 1000,
  };
}
export function amount(r) { return r() < 0.8 ? 500 + Math.floor(r() * 49500) : 50000 + Math.floor(r() * 450000); }
export function recipient(r) { const b = pick(r, BANKS); return { bank: b.name, nuban: nuban(b.code, digits(r, 9)), name: `${pick(r, FIRST)} ${pick(r, LAST)}` }; }
const NARR = ["Rent", "School fees", "Foodstuff", "Thanks", "Transport", "Business", "Family support", "Airtime"];
export const narration = (r) => pick(r, NARR);
export function loanRef(r) { return `LGN-LN-${digits(r, 8)}`; }
export const chatTemplates = [
  (c, a) => `Good morning. My transfer of ₦${a.toLocaleString("en-NG")} to ${recipient(rng(a)).nuban} failed but my wallet was debited. Please help.`,
  (c, a) => `Abeg my transfer of ₦${a.toLocaleString("en-NG")} to ${recipient(rng(a)).nuban} no go, my BVN na ${c.bvn}. Wetin happen?`,
  (c) => `I want to update my BVN on the app. It is ${c.bvn}.`,
  (c) => `Please when will my loan be approved? My account is ${c.nuban}.`,
  () => `How do I change my transaction PIN?`,
  () => `Una app dey hang since morning, I no fit log in.`,
  (c) => `Please confirm if my phone number ${c.phone} is the one on my profile.`,
  () => `What is the limit for sending money in one day?`,
];
