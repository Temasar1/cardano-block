// import crypto from 'crypto';
// /**
//  * Generates a SHA-256 hash from an array.
//  * @param {Array} arr - The array to hash.
//  * @returns {string} - The SHA-256 hash in hexadecimal format.
//  */
// function sha256HashArray(arr: any[]) {
//     if (!Array.isArray(arr)) {
//         throw new TypeError('Input must be an array.');
//     }

//     // Convert array to a JSON string for consistent representation
//     const jsonString = JSON.stringify(arr);

//     return crypto
//         .createHash('sha256')
//         .update(jsonString, 'utf8')
//         .digest('hex');
// }

// try {
//     const myArray = [1, 2, 3, 'hello', { a: 10 }];
//     const hash = sha256HashArray(myArray);
//     console.log(`Array: ${JSON.stringify(myArray)}`);
//     console.log(`SHA-256 Hash: ${hash}`);
// } catch (err) {
//     console.error('Error:', (err as Error).message);
// }

