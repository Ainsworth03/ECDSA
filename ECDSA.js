//by my algo

//curve: x^3 + ax + b mod r


/**Find inverse of a number n modulo p (n^-1 mod p)
* @param {number} n  - number to find it's inverse
* @param {number} p - the modulo
* @returns {number} the inverse of n mod p
*/
const findInverse = (n, p) =>{
    while(n < 0){n += p}
    n = n % p
    for (let x = 1; x < p; x++){
        if((n * x) % p === 1){
            return x
        }
    }
}

/**Find gradient for additions according to the elliptic curve over modulo p rules
 * @param {Number[]} point_1 - the first point for addition 
 * @param {Number[]} point_2 - the second point for addition
 * @param {number} p - the modulo (divisor)
 * @param {number} a - the a value of curve y^2 = x^3 + ax + b
 * @returns {number} the gradient of two points following the elliptic curve rules.
 */
const findGradient = (point_1, point_2, p, a) => {

    if (point_1[0] != point_2[0]){
        //Case 1 where two x are different
        //return: (y2 - y1) / (x2 - x1)
        return ((point_2[1] - point_1[1]) * findInverse(point_2[0] - point_1[0], p)) % p


    }else if(point_1[0] == point_2[0] && point_1[1] == point_2[1]){
        //case 3 where both the same point
        //return: (3x_1^2 + a) / (2 * y_1)
        return (((3 * point_1[0] * point_1[0] ) + a) * findInverse(2 * point_1[1], p)) % p   

    }
}

/**
 * Function for adding two points with elliptic curve over Zp addition rules
 * @param {Function} findGradient - function to find the gradient of two points 
 * @param {Number[]} point_1 - first point 
 * @param {Number[]} point_2 - second point
 * @param {Number} p - the modulo (divisor) 
 * @param {Number} a  - the a value of curve y^2 = x^3 + ax + b
 * @returns {number[]} addition result based on elliptic curve rules
 */
const pointAdd = (findGradient, point_1, point_2, p, a) => {
    if (point_1[0] == point_2[0] && -1 * (point_1[1] - p) == point_2[1]){
        return Object.freeze([Infinity, Infinity])
    
    }else if (point_1[0] == Infinity && point_1[1] == Infinity){
        return point_2

    }else if(point_2[0] == Infinity && point_2[1] == Infinity){
        return point_1
    
    }else{
        const gradient = findGradient(point_1, point_2, p, a)
        x3 = (gradient ** 2 - point_1[0] - point_2[0]) % p
        y3 = (gradient * (point_1[0] - x3) - point_1[1]) % p
        while(x3 < 0){x3 += p}
        while(y3 < 0){y3 += p}
        return Object.freeze([x3, y3])
    }    
}

/**
 * 
 * @param {Function} pointAdd - addition function
 * @param {number[]} point_1 - point to multiply
 * @param {number} p - the modulo (divisor)
 * @param {number} a - the a value of curve y^2 = x^3 + ax + b
 * @param {number} scalar - scalar multiplier 
 * @returns {number[]} point result from multiplication
 */
const pointMulti = (pointAdd, point_1, p, a, scalar) => {
    let point_temp = point_1
    for (let i = 0; i < scalar-1; i++){
        point_temp = pointAdd(findGradient, point_temp, point_1, p, a)
        //console.log(point_temp)
    }
    const point = point_temp
    return point
}

/**
 * 
 * @param {number} privKey - signer's private key  
 * @param {number[]} base_point - the choosen base point G over the curve
 * @param {number} p - the modulo (divisor)
 * @param {number} a - the a value of curve y^2 = x^3 + ax + b
 * @returns {number[]} list of sender's public key [a,b]
 */
const generateKey = (privKey, base_point, p, a) => {
    return pointMulti(pointAdd, base_point, p, a, privKey)
}

/**
 * 
 * @param {Function} pointMulti - point multiplication function 
 * @param {number[]} base_point - base point G over the curve
 * @param {number} p - the modulo (divisor)
 * @param {number} a - the a value of curve y^2 = x^3 + ax + b
 * @param {number} order - order of the point in the curve
 * @param {number} privKey - signer's private key
 * @param {number} message - message to sign
 * @param {number} k - selected k value for signing
 * @returns {number[]} [R,S] indicates ECDSA's signed message
 */
const signing = (pointMulti, base_point, p, a, order, privKey, message, k) => {
    //const pubKey = pointMulti(pointAdd, base_point, p, a, privKey)
    const k_times_base = pointMulti(pointAdd, base_point, p, a, k)
    const random_num_inverse = findInverse(k, order)
    const r = k_times_base[0] % order
    const sign_message = (random_num_inverse * (message + privKey * r)) % order
    //console.log(privKey * r)
    return Object.freeze([r, sign_message])

}

/**
 * 
 * @param {*} pointMulti - point multiplication function
 * @param {*} base_point - base point G over the curve
 * @param {*} order - order of the point in the curve
 * @param {*} pubKey - signer's public key
 * @param {*} signed - signed message [R,S]
 * @param {*} message - message to check (verify)
 * @param {*} p - the modulo (divisor)
 * @param {*} a - the a value of curve y^2 = x^3 + ax + b
 * @returns {boolean} returns true if the message valid, and false if message invalid
 */
const verifying = (pointMulti, base_point, order, pubKey, signed, message, p, a) => {
    const s_inverse = findInverse(signed[1], order)
    const u_1 = (s_inverse * message) % order
    const u_2 = (s_inverse * signed[0]) % order
    const X = pointAdd(findGradient, pointMulti(pointAdd, base_point, p, a, u_1), pointMulti(pointAdd, pubKey, p, a, u_2), p, a)
    //console.log(`signed[1]: ${signed[1]},s_inverse: ${s_inverse}, U1: ${u_1}, u2: ${u_2}, X: ${X}`)
    if (signed[0] == X[0]){
        return true
    }else{
        return false
    }
}


// ================ EDIT HERE ======================================== 

//Variable:
const a = -3               //the a value of curve y^2 = x^3 + ax + b
const b = 69424            //the b value of curve y^2 = x^3 + ax + b
const p = 114973           //the modulo (divisor; curve over Zp)
const order = 114467       //order of the base point over the curve (G)
const x1 = 11570           //x-axis of the base point (x,ty
const y1= 42257            //y-axis of the base point (x,y)
const point = [x1, y1]     //base point G
const privKey = 86109
const message = 1789679805
const k = 84430

const encrypted = signing(pointMulti, point, p, a, order, privKey, message, k)
const pubKey = generateKey(privKey, point, p, a)
const verify = verifying(pointMulti, point, order, pubKey, encrypted, message, p, a)

console.log(`encrypted: ${encrypted}`)
console.log(`public key: ${pubKey}`)
console.log(`verified ${verify}`)


// This part of the code is for testing, uncomment on the code u needed
/*
//const gradient_res = findGradient(point, point, p, a)
//const add = pointAdd(gradient_res, point, point, p)
//const result = pointMulti(pointAdd, point, p, a, scalar)

//const scalar = 38
//console.log(`Gradient: ${gradient_res}`)
//console.log(`result of addition: ${add}`)
//console.log(`Result: ${result}`)


const inverse = findInverse(2, 17)
console.log(`Inverse is: ${inverse}`)
*/