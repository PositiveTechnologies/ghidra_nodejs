function lsh(m, n) {
	n = n << m;
	return n
}
function rsh(m, n) {
	n = n >> m;
	return  n;
}
function mul_add_div_sub(m, n) {
	n = (n*m + m)/ n - n;
	return n
}

function or_and(m, n) {
	n = n & (m | n);
	return n
}
function brsh(m, n) {
	n = n >>> m;
	return  n;
}

function pow(m, n) {
	n = n ** m;
	return  n;
}

function xor(m, n) {
	n = n^m;
	return  n;
}

function mod(m, n) {
	n = n%m;
	return  n;
}