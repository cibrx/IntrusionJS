"use strict";

const fs = require("fs");
const path = require("path");
const { pki, md } = require("node-forge");
const mkdirp = require("mkdirp");
const async = require("async");

const CA_ATTRIBUTES = [
    { name: "commonName", value: "IntrusionJSCA" },
    { name: "countryName", value: "Internet" },
    { shortName: "ST", value: "Internet" },
    { name: "localityName", value: "Internet" },
    { name: "organizationName", value: "IntrusionJS Interception Proxy" },
    { shortName: "OU", value: "CA" },
];

const CA_EXTENSIONS = [
    { name: "basicConstraints", cA: true },
    {
        name: "keyUsage",
        keyCertSign: true,
        digitalSignature: true,
        nonRepudiation: true,
        keyEncipherment: true,
        dataEncipherment: true,
    },
    {
        name: "extKeyUsage",
        serverAuth: true,
        clientAuth: true,
        codeSigning: true,
        emailProtection: true,
        timeStamping: true,
    },
    {
        name: "nsCertType",
        client: true,
        server: true,
        email: true,
        objsign: true,
        sslCA: true,
        emailCA: true,
        objCA: true,
    },
    { name: "subjectKeyIdentifier" },
];

const SERVER_ATTRIBUTES = [
    { name: "countryName", value: "Internet" },
    { shortName: "ST", value: "Internet" },
    { name: "localityName", value: "Internet" },
    { name: "organizationName", value: "IntrusionJS Interception Proxy" },
    { shortName: "OU", value: "IntrusionJS Interception Proxy Server Certificate" },
];

const SERVER_EXTENSIONS = [
    { name: "basicConstraints", cA: false },
    {
        name: "keyUsage",
        keyCertSign: false,
        digitalSignature: true,
        nonRepudiation: false,
        keyEncipherment: true,
        dataEncipherment: true,
    },
    {
        name: "extKeyUsage",
        serverAuth: true,
        clientAuth: true,
    },
    {
        name: "nsCertType",
        client: true,
        server: true,
    },
    { name: "subjectKeyIdentifier" },
];


class CA {
    constructor() {
        this.baseCAFolder = '';
        this.certsFolder = '';
        this.keysFolder = '';
        this.CAcert = null;
        this.CAkeys = null;
    }

    create(caFolder, callback) {
        const ca = new CA();
        ca.baseCAFolder = caFolder;
        ca.certsFolder = path.join(ca.baseCAFolder, "certs");
        ca.keysFolder = path.join(ca.baseCAFolder, "keys");

        mkdirp.sync(ca.baseCAFolder);
        mkdirp.sync(ca.certsFolder);
        mkdirp.sync(ca.keysFolder);

        async.series([
            cb => {
                if (fs.existsSync(path.join(ca.certsFolder, "ca.pem"))) {
                    ca.loadCA(cb);
                } else {
                    ca.generateCA(cb);
                }
            }
        ], err => callback(err, ca));
    }

    randomSerialNumber() {
        return Array.from({ length: 4 }, () => `00000000${Math.floor(Math.random() * 256 ** 4).toString(16)}`.slice(-8)).join('');
    }

    getPem() {
        return pki.certificateToPem(this.CAcert);
    }

    generateCA(callback) {
        pki.rsa.generateKeyPair({ bits: 2048 }, (err, keys) => {
            if (err) return callback(err);

            const cert = pki.createCertificate();
            cert.publicKey = keys.publicKey;
            cert.serialNumber = this.randomSerialNumber();
            cert.validity.notBefore = new Date();
            cert.validity.notBefore.setDate(cert.validity.notBefore.getDate() - 1);
            cert.validity.notAfter = new Date();
            cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);

            cert.setSubject(CA_ATTRIBUTES);
            cert.setIssuer(CA_ATTRIBUTES);
            cert.setExtensions(CA_EXTENSIONS);
            cert.sign(keys.privateKey, md.sha256.create());

            this.CAcert = cert;
            this.CAkeys = keys;

            async.parallel([
                cb => fs.writeFile(path.join(this.certsFolder, "ca.pem"), pki.certificateToPem(cert), cb),
                cb => fs.writeFile(path.join(this.keysFolder, "ca.private.key"), pki.privateKeyToPem(keys.privateKey), cb),
                cb => fs.writeFile(path.join(this.keysFolder, "ca.public.key"), pki.publicKeyToPem(keys.publicKey), cb),
            ], callback);
        });
    }

    loadCA(callback) {
        async.auto({
            certPEM: cb => fs.readFile(path.join(this.certsFolder, "ca.pem"), "utf-8", cb),
            keyPrivatePEM: cb => fs.readFile(path.join(this.keysFolder, "ca.private.key"), "utf-8", cb),
            keyPublicPEM: cb => fs.readFile(path.join(this.keysFolder, "ca.public.key"), "utf-8", cb),
        }, (err, results) => {
            if (err) return callback(err);

            this.CAcert = pki.certificateFromPem(results.certPEM);
            this.CAkeys = {
                privateKey: pki.privateKeyFromPem(results.keyPrivatePEM),
                publicKey: pki.publicKeyFromPem(results.keyPublicPEM),
            };
            callback();
        });
    }

    generateServerCertificateKeys(hosts, cb) {
        const mainHost = Array.isArray(hosts) ? hosts[0] : hosts;
        const keysServer = pki.rsa.generateKeyPair(2048);
        const certServer = pki.createCertificate();

        certServer.publicKey = keysServer.publicKey;
        certServer.serialNumber = this.randomSerialNumber();
        certServer.validity.notBefore = new Date();
        certServer.validity.notBefore.setDate(certServer.validity.notBefore.getDate() - 1);
        certServer.validity.notAfter = new Date();
        certServer.validity.notAfter.setFullYear(certServer.validity.notBefore.getFullYear() + 1);

        const attrsServer = [{ name: "commonName", value: mainHost }, ...SERVER_ATTRIBUTES];
        certServer.setSubject(attrsServer);
        certServer.setIssuer(this.CAcert.issuer.attributes);
        certServer.setExtensions([
            ...SERVER_EXTENSIONS,
            {
                name: "subjectAltName",
                altNames: hosts.map(host => host.match(/^[\d.]+$/) ? { type: 7, ip: host } : { type: 2, value: host }),
            },
        ]);

        certServer.sign(this.CAkeys.privateKey, md.sha256.create());

        const certPem = pki.certificateToPem(certServer);
        const keyPrivatePem = pki.privateKeyToPem(keysServer.privateKey);
        const keyPublicPem = pki.publicKeyToPem(keysServer.publicKey);

        const certFileName = mainHost.replace(/\*/g, "_");

        fs.writeFile(`${this.certsFolder}/${certFileName}.pem`, certPem, err => {
            if (err) console.error(`Failed to save certificate to disk in ${this.certsFolder}`, err);
        });
        fs.writeFile(`${this.keysFolder}/${certFileName}.key`, keyPrivatePem, err => {
            if (err) console.error(`Failed to save private key to disk in ${this.keysFolder}`, err);
        });
        fs.writeFile(`${this.keysFolder}/${certFileName}.public.key`, keyPublicPem, err => {
            if (err) console.error(`Failed to save public key to disk in ${this.keysFolder}`, err);
        });

        cb(certPem, keyPrivatePem);
    }

    getCACertPath() {
        return path.join(this.certsFolder, "ca.pem");
    }
}

module.exports = CA;
