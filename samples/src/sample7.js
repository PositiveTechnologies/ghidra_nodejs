function User(name) {
  this.name = name;

  this.sayHi = function() {
    alert( "Name: " + this.name );
  };
}

let vasya = new User("Vasya");

vasya.sayHi();