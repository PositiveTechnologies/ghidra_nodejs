function lsh(n) {
	n = n << 1;
	return n
}
function rsh(n) {
	n = n >> 1;
	return  n;
}
function mul_add_div_sub(n) {
	n = (n*2 + 55)/ 10 - 1;
	return n
}
function or_and(n) {
	n = n & 0x5f | 0x09;
	return n
}
function not(n) {
	return ~n
;
}
function brsh(n) {
	n = n >>> 1;
	return  n;
}

function pow(n) {
	n = n ** 3;
	return  n;
}

function xor(n) {
	n = n^3;
	return  n;
}

function mod(n) {
	n = n%3;
	return  n;
}
