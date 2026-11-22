import { useMDXComponents as getThemeComponents } from "nextra-theme-docs";
import { Shot } from "./components/Shot";
import { Cards, Ent, Early } from "./components/Cards";
import { CountryTable, LawTable } from "./components/CountryTable";
import { Steps } from "nextra/components";

const themeComponents = getThemeComponents();

export function useMDXComponents(components) {
  return { ...themeComponents, Shot, Cards, Ent, Early, Steps, CountryTable, LawTable, ...components };
}
