import { Convert } from "./secrets_gen"; // typed, generated

const typed = Convert.toMonosecret(resolved.fieldsJson());
console.log(typed.DATABASE_URL);
