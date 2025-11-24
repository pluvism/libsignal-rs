"use strict";

const native = require('../index.node');
const curveJs = require('curve25519-js');

function getNative(snake, camel) {
    if (!native) throw new Error('Native binding ../index.node is not loaded.');
    if (camel && typeof native[camel] === 'function') return native[camel];
    if (snake && typeof native[snake] === 'function') return native[snake];
    throw new Error(`Native function ${camel || snake} is not available. Build or provide the native binding (../index.node).`);
}

function validatePrivKey(privKey) {
    if (privKey === undefined) {
        throw new Error("Undefined private key");
    }
    if (!(privKey instanceof Buffer)) {
        throw new Error(`Invalid private key type: ${privKey?.constructor?.name}`);
    }
    if (privKey.byteLength != 32) {
        throw new Error(`Incorrect private key length: ${privKey?.byteLength}`);
    }
}

function scrubPubKeyFormat(pubKey) {
    if (!(pubKey instanceof Buffer)) {
        throw new Error(`Invalid public key type: ${pubKey?.constructor?.name}`);
    }
    if (pubKey === undefined || ((pubKey.byteLength != 33 || pubKey[0] != 5) && pubKey.byteLength != 32)) {
        throw new Error("Invalid public key");
    }
    if (pubKey.byteLength == 33) {
        return pubKey.slice(1);
    } else {
        console.error("WARNING: Expected pubkey of length 33, please report the ST and client that generated the pubkey");
        return pubKey;
    }
}


function unclampEd25519PrivateKey(clampedSk) {
    const unclampedSk = new Uint8Array(clampedSk);

    // Fix the first byte
    unclampedSk[0] |= 6; // Ensure last 3 bits match expected `110` pattern

    // Fix the last byte
    unclampedSk[31] |= 128; // Restore the highest bit
    unclampedSk[31] &= ~64; // Clear the second-highest bit

    return unclampedSk;
}

exports.generateKeyPair = function() {
    const fn = getNative('generate_key_pair', 'generateKeyPair');
    const kp = fn();
    const priv = kp.privateKey;
    const pub = kp.publicKey;
    return { privKey: Buffer.from(priv), pubKey: Buffer.from(pub) };
};



exports.getPublicFromPrivateKey = function(privKey) {
    validatePrivKey(privKey);
    const fn = getNative('get_public_from_private_key', 'getPublicFromPrivateKey');
    return Buffer.from(fn(privKey));
};

exports.calculateAgreement = function(pubKey, privKey) {
    validatePrivKey(privKey);
    const fn = getNative('calculate_agreement', 'calculateAgreement');
    return Buffer.from(fn(pubKey, privKey));
};

exports.calculateSignature = function(privKey, message) {
    validatePrivKey(privKey);
    if (!message) {
        throw new Error("Invalid message");
    }
    const fn = getNative('calculate_signature', 'calculateSignature');
    return Buffer.from(fn(privKey, message));
};

exports.verifySignature = function(pubKey, msg, sig, isInit = false) {
    pubKey = scrubPubKeyFormat(pubKey);
    if (!pubKey || pubKey.byteLength != 32) {
        throw new Error("Invalid public key ok");
    }
    if (!msg) {
        throw new Error("Invalid message");
    }
    if (!sig || sig.byteLength != 64) {
        throw new Error("Invalid signature");
    }
    
    const fn = getNative('verify_signature', 'verifySignature');
    return fn(pubKey, msg, sig, isInit);
};

