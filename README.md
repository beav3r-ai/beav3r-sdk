# Beav3r SDK

Standalone source repo for the public Beav3r packages:

- `@beav3r/protocol`
- `@beav3r/sdk`

Install from npm:

```bash
npm install @beav3r/sdk
```

The SDK depends on `@beav3r/protocol`, and both packages are maintained together in this repo.

## Packages

- [`packages/protocol`](./packages/protocol)
- [`packages/sdk`](./packages/sdk)

## Development

Build both packages:

```bash
npm run build:packages
```

Publish versions with Changesets:

```bash
npm run version-packages
npm run release-packages
```
