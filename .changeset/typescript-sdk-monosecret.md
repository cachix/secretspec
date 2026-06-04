---
"@monosecret/sdk": major
---

Add the initial TypeScript SDK package for invoking Monosecret from Node.js applications.

```ts
import { MonosecretClient } from '@monosecret/sdk';

const monosecret = new MonosecretClient();
const databaseUrl = await monosecret.get('DATABASE_URL', {
  profile: 'development',
});

const environment = await monosecret.loadEnvironment({
  include: ['DATABASE_URL', 'API_KEY'],
});
```
