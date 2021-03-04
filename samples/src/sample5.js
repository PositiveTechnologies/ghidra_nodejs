let user = {
  name: "Ivan",
  sizes: {
    height: 182,
    width: 50
  }
};

let clone = Object.assign({}, user);

if( user.sizes === clone.sizes ){ 
	console.log("Old width: ", clone.sizes.width)
	user.sizes.width++;       
	console.log("New width: ", clone.sizes.width)
}