"use strict";

const native = require('../index.node');

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

exports.generateKeyPair = function() {
    const fn = getNative('generate_key_pair', 'generateKeyPair');
    return fn();
};



exports.getPublicFromPrivateKey = function(privKey) {
    validatePrivKey(privKey);
    const fn = getNative('get_public_from_private_key', 'getPublicFromPrivateKey');
    return fn(privKey)
};

exports.calculateAgreement = function(pubKey, privKey) {
    validatePrivKey(privKey);
    const fn = getNative('calculate_agreement', 'calculateAgreement');
    return fn(pubKey, privKey)
};

exports.calculateSignature = function(privKey, message) {
    validatePrivKey(privKey);
    if (!message) {
        throw new Error("Invalid message");
    }
    const fn = getNative('calculate_signature', 'calculateSignature');
    return fn(privKey, message)
};

exports.verifySignature = function(pubKey, msg, sig, isInit = false) {
    if (!msg) {
        throw new Error("Invalid message");
    }
    if (!sig || sig.byteLength != 64) {
        throw new Error("Invalid signature");
    }
    
    const fn = getNative('verify_signature', 'verifySignature');
    return fn(pubKey, msg, sig, isInit);
};

