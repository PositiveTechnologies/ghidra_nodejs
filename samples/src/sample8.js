const entries = new Map([
  ['123', 23],
  ['abc', 'de']
]);

const obj = Object.fromEntries(entries);
console.log(obj);

