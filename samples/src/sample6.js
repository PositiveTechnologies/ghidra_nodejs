function sumAll(...args) { 
  let sum = 0;

  for (let arg of args) sum += arg;

  return sum;
}

setTimeout(function() {
  sumAll(0.1, 1.34, 2.346, 8.3165);
}, 1000);
