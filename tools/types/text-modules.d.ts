// Bun embeds Markdown imported with `with { type: "text" }` as a string.
declare module "*.md" {
  const text: string;
  export default text;
}
