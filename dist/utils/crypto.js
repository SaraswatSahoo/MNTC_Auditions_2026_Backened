"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateOtp6 = generateOtp6;
exports.sha256 = sha256;
const js_sha256_1 = require("js-sha256");
function generateOtp6() {
    return String(Math.floor(100000 + Math.random() * 900000));
}
function sha256(input) {
    return (0, js_sha256_1.sha256)(input);
}
