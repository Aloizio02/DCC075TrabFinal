const crypto = require('crypto');
const fs = require('fs');
const CryptoJS = require('crypto-js');
const readline = require('readline').createInterface({
    input: process.stdin,
    output: process.stdout
});

// ----------------------------------------------------------------------------- Etapa de criptografia -----------------------------------------------------------------------------
// Função principal para a criptografia
async function encrypt() {
    // Pede ao usuário o caminho contendo a chave pública do destinatário
    let publicKeyPath = await getPublicKeyPath();
    if(!fs.existsSync(publicKeyPath)) {
        console.log(`Arquivo de chave pública não encontrado. Verifique e tente novamente!`);
        return;
    }

    // Salva a mensagem informada pelo usuário
    const inputMessage = await getInputMessage();

    // Gera uma sBox randomicamente
    const sBox = generateSboxRandomly();

    // Criptografa a mensagem com a cifra de Feistel
    const encryptedMessage = feistelCipherBuffer(Buffer.from(inputMessage), sBox, 16);
    console.log(`Mensagem criptografada: ${encryptedMessage.toString('hex')}`);

    // Salva a mensagem criptografada em um arquivo
    fs.writeFileSync('encrypted_message.txt', encryptedMessage.toString('hex'));
    console.log('Mensagem criptografada salva em "encrypted_message.txt".');

    // Gera uma chave AES
    const aesKey = crypto.randomBytes(32).toString('hex');
    const encryptedSBox = encryptWithAES(JSON.stringify(sBox), aesKey);

    // Criptografa a chave AES usando a chave pública RSA do destinatário
    const encryptedAESKey = encryptWithRSA(aesKey, publicKeyPath);

    // Salva o sBox criptografado e a chave AES criptografada
    fs.writeFileSync('encrypted_sbox.dat', encryptedSBox);
    fs.writeFileSync('encrypted_aes_key.dat', encryptedAESKey);

    console.log('sBox salvo em "encrypted_sbox.dat".');
    console.log('Chave AES salva em "encrypted_aes_key.dat".');
}

// Recebe a mensagem de entrada fornecida pelo usuário
async function getInputMessage() {
    return new Promise((resolve, reject) => {
        readline.question("Informe uma mensagem para criptografar: ", (message) => {
            if (message) {
                resolve(message);
            } else {
                console.log("Entrada invalida! Tente novamente.\n");
                getInputMessage().then(resolve).catch(reject);
            }
        });
    });
}

// Recebe o caminho da chave pública do destinatário
async function getPublicKeyPath() {
    return new Promise((resolve) => {
        readline.question("Informe o caminho para a chave publica do destinatario: ", (path) => {
            resolve(path.trim());
        });
    });
}

// ---------------------------------------------- Primeira camada: Algoritmo de Feistel na mensagem ----------------------------------------------
// Aplica o algoritmo de Feistel para um buffer de bytes
function feistelCipherBuffer(inputBuffer, sBox, rounds) {
    if (inputBuffer.length % 2 !== 0) {
        inputBuffer = Buffer.concat([inputBuffer, Buffer.from([0x00])]);
    }

    function feistel(left, right, rounds) {
        for (let i = 0; i < rounds; i++) {
            const temp = right;
            const row = right & 0x0F;
            const col = (right >> 4) & 0x0F;
            right = left ^ sBox[row][col];
            left = temp;
        }
        return [left, right];
    }

    let outputBuffer = Buffer.alloc(inputBuffer.length);
    for (let i = 0; i < inputBuffer.length; i += 2) {
        if (i + 1 < inputBuffer.length) {
            const [left, right] = feistel(inputBuffer[i], inputBuffer[i + 1], rounds);
            outputBuffer[i] = left;
            outputBuffer[i + 1] = right;
        } else {
            let byte = inputBuffer[i];
            for (let j = 0; j < rounds; j++) {
                const row = byte & 0x0F;
                const col = (byte >> 4) & 0x0F;
                byte = byte ^ sBox[row][col];
            }
            outputBuffer[i] = byte;
        }
    }

    return outputBuffer;
}

// Gerar randomicamente uma sBox de 256 bits (usando o módulo crypto do node.js)
function generateSboxRandomly() {
    const sBox = [];
    const mDimension = 16;
    const randomBytes = crypto.randomBytes(mDimension * mDimension * 2);

    for (let i = 0; i < mDimension * mDimension; i++) {
        const value = randomBytes.readUInt16BE(i * 2);
        sBox.push(value);
    }

    // Transformar em uma matriz 16 x 16
    const matrix = [];
    for (let i = 0; i < mDimension; i++) {
        matrix.push(sBox.slice(i * mDimension, (i + 1) * mDimension));
    }
    return matrix;
}

// ---------------------------------------------- Segunda camada: AES aplicado no sBox da Cifra de Feistel ----------------------------------------------
// Função que será usada para criptografar a sBox em uma chave AES
function encryptWithAES(data, aesKey) {
    const ciphertext = CryptoJS.AES.encrypt(data, aesKey).toString();
    return ciphertext;
}

// ---------------------------------------------- Terceira camada: RSA aplicada na chave AES ----------------------------------------------
// Função para criptografar dados usando a chave pública RSA
function encryptWithRSA(data, receivePublicKey) {
    const publicKey = fs.readFileSync(receivePublicKey, 'utf8');
    return crypto.publicEncrypt(publicKey, Buffer.from(data));
}

// ----------------------------------------------------------------------------- Etapa de descriptografia -----------------------------------------------------------------------------
// Função principal para descriptografia
async function decrypt() {
    const privateKeyPath = await getPrivateKeyPath();
    if (!fs.existsSync(privateKeyPath)) {
        console.log(`Arquivo da chave privada não encontrado. Verifique e tente novamente!`);
        return;
    }
    const passphrase = await new Promise((resolve) => {
        readline.question("Informe a senha da chave RSA privada (se houver senha): ", resolve);
    });
    const encryptedAESKeyPath = await getEncryptedAESKeyPath();
    if (!fs.existsSync(encryptedAESKeyPath)) {
        console.log(`Arquivo da chave AES criptografada não encontrado. Verifique e tente novamente!`);
        return;
    }
    const encryptedSBoxPath = await getEncryptedSBoxPath();
    if (!fs.existsSync(encryptedSBoxPath)) {
        console.log(`Arquivo do sBox criptografado não encontrado. Verifique e tente novamente!`);
        return;
    }
    const encryptedMessagePath = await getEncryptedMessagePath();
    if (!fs.existsSync(encryptedMessagePath)) {
        console.log(`Arquivo da mensagem criptografada não encontrado. Verifique e tente novamente!`);
        return;
    }

    // Lê o conteúdo dos arquivos
    const encryptedAESKey = fs.readFileSync(encryptedAESKeyPath);
    const encryptedSBox = fs.readFileSync(encryptedSBoxPath, 'utf8');
    const encryptedMessageHex = fs.readFileSync(encryptedMessagePath, 'utf8');

    // Converte a mensagem criptografada de hexadecimal para buffer
    const encryptedMessage = Buffer.from(encryptedMessageHex, 'hex');

    // Descriptografa a chave AES usando a chave privada RSA
    const aesKey = decryptWithRSA(encryptedAESKey, privateKeyPath, passphrase).toString('utf8');

    // Descriptografa o sBox usando a chave AES
    const decryptedSBox = decryptWithAES(encryptedSBox, aesKey);

    // Descriptografa a mensagem usando o sBox descriptografado
    const decryptedMessageBuffer = feistelDecipherBuffer(encryptedMessage, decryptedSBox, 16);

    console.log(`Mensagem descriptografada : ${decryptedMessageBuffer.toString('utf8')}`);
}

// Recebe do usuário o path da chave privada
async function getPrivateKeyPath() {
    return new Promise((resolve) => {
        readline.question("Informe o caminho para a chave RSA privada: ", (path) => {
            resolve(path.trim());
        });
    });
}

// Recebe do usuário o path da chave AES criptografada pelo RSA
async function getEncryptedAESKeyPath() {
    return new Promise((resolve) => {
        readline.question("Informe o caminho para a chave AES criptografada: ", (path) => {
            resolve(path.trim());
        });
    });
}

// Recebe do usuário o path da sBox usada em Feistel criptografada pelo AES
async function getEncryptedSBoxPath() {
    return new Promise((resolve) => {
        readline.question("Informe o caminho para o sBox criptografado: ", (path) => {
            resolve(path.trim());
        });
    });
}

// Recebe do usuário o path da mensagem criptografada
async function getEncryptedMessagePath() {
    return new Promise((resolve) => {
        readline.question("Informe o caminho para a mensagem criptografada: ", (path) => {
            resolve(path.trim());
        });
    });
}

// Função para descriptografar dados usando a chave privada RSA
function decryptWithRSA(encryptedData, privateKeyPath, passphrase) {
    const privateKey = fs.readFileSync(privateKeyPath, 'utf8');
    return crypto.privateDecrypt(
        {
            key: privateKey,
            passphrase: passphrase,
        },
        encryptedData
    );
}

// Função para descriptografar o sBox
function decryptWithAES(ciphertext, aesKey) {
    const bytes = CryptoJS.AES.decrypt(ciphertext, aesKey);
    return JSON.parse(bytes.toString(CryptoJS.enc.Utf8));
}

// Aplica o algoritmo de Feistel para decifrar o buffer de bytes
function feistelDecipherBuffer(encryptedBuffer, sBox, rounds) {
    function feistelDecipher(left, right, rounds) {
        for (let i = 0; i < rounds; i++) {
            const temp = left;
            const row = left & 0x0F;
            const col = (left >> 4) & 0x0F;
            left = right ^ sBox[row][col];
            right = temp;
        }
        return [left, right];
    }

    let outputBuffer = Buffer.alloc(encryptedBuffer.length);
    for (let i = 0; i < encryptedBuffer.length; i += 2) {
        if (i + 1 < encryptedBuffer.length) {
            const [left, right] = feistelDecipher(encryptedBuffer[i], encryptedBuffer[i + 1], rounds);
            outputBuffer[i] = left;
            outputBuffer[i + 1] = right;
        } else {
            let byte = encryptedBuffer[i];
            for (let j = 0; j < rounds; j++) {
                const row = byte & 0x0F;
                const col = (byte >> 4) & 0x0F;
                byte = byte ^ sBox[row][col];
            }
            outputBuffer[i] = byte;
        }
    }
    
    if (outputBuffer[outputBuffer.length - 1] === 0x00) {
        outputBuffer = outputBuffer.slice(0, -1);
    }

    return outputBuffer;
}

// Chamadas principais para as funções de criptografia, descriptografia e ambiente de testes
(async () => {
    console.log("Escolha uma opção: ");
    console.log("1. Criptografar uma mensagem");
    console.log("2. Descriptografar uma mensagem");

    readline.question("Opção: ", async (option) => {
        if (option === '1') {
            await encrypt();
        } else if (option === '2') {
            await decrypt();
        } else {
            console.log("Opção inválida!");
        }
        readline.close();
    });
})();