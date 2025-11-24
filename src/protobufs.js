"use strict";

const path = require('path');
const protobuf = require('protobufjs');

const protodir = path.resolve(__dirname, '../protos/');
const whisper = protobuf.loadSync(path.join(protodir, 'WhisperTextProtocol.proto')).lookup('textsecure');
const local = protobuf.loadSync(path.join(protodir, 'LocalStorageProtocol.proto')).lookup('textsecure');

module.exports = {
    WhisperMessage: whisper.lookup('WhisperMessage'),
    PreKeyWhisperMessage: whisper.lookup('PreKeyWhisperMessage'),
    SenderKeyDistributionMessage: whisper.lookup('SenderKeyDistributionMessage'),
    SenderKeyMessage: whisper.lookup('SenderKeyMessage'),
    SenderKeyStateStructure: local.lookup('SenderKeyStateStructure'),
    SenderChainKey: local.lookup('SenderChainKey'),
    SenderSigningKey: local.lookup('SenderSigningKey'),
};
