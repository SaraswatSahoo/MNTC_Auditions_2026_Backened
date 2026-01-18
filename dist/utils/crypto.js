"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.sha256 = sha256;
exports.randomToken64 = randomToken64;
const crypto_1 = __importDefault(require("crypto"));
const js_sha256_1 = require("js-sha256");
function sha256(input) {
    return (0, js_sha256_1.sha256)(input);
}
// Cryptographically secure random token [web:723]
function randomToken64() {
    return crypto_1.default.randomBytes(32).toString("hex");
}
