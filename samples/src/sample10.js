let timerId = setTimeout(() => alert("nothing happens"), 1000);
console.log("timerId:", timerId);

clearTimeout(timerId);
console.log("timerId:", timerId);
