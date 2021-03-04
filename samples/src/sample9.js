function* generate() {
  let result = yield "2 + 2 = ?"; 
}

let generator = generate();

let question = generator.next().value;

try {
  generator.throw(new Error("No answer found in my database"));
} catch(e) {
  alert("Error");
}