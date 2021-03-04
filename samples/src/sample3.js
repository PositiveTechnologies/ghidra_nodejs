function sample3(n) {
	alert( n || 0 || 1 ); 
	if (n != undefined) alert( !n );
}

sample3(undefined);