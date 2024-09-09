const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const CryptoJS = require('crypto-js');
const readline = require('readline').createInterface({
    input: process.stdin,
    output: process.stdout
});

var publicKeyTestPath;
var privateKeyTestPath;

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

// ----------------------------------------------------------------------------- Ambiente de testes -----------------------------------------------------------------------------
// Função principal para o ambiente de testes
async function testEnvironment() {
    console.log("Escolha o tipo de teste a ser executado:");
    console.log("1. Testes de Performance");
    console.log("2. Testes de Segurança");

    const option = await new Promise((resolve) => {
        readline.question("Opção: ", (option) => resolve(option.trim()));
    });

    if (option === '1') {
        await performanceTests();
    } else if (option === '2') {
        await securityTests();
    } else {
        console.log("Opção inválida! Tente novamente.");
        await testEnvironment();
    }
}

// --------------------------------------------------------------------- Testes de performance ---------------------------------------------------------------------

// Função para executar testes de performance
async function performanceTests(){
    // Salva a mensagem informada pelo usuário
    const inputMessage = await getInputMessage();

    // Cria as chaves RSA locais para criptografar e descriptografar a mensagem
    createKeys();

    // Chama função que executa os testes de performance
    processesPerformanceTests(inputMessage);
}

// Executa testes de performance
function processesPerformanceTests(inputMessage) {
    console.log("--------------------------------------- Resultados da criptografia ---------------------------------------");
    // Criptografia usando Feistel, AES e RSA
    const feistelAesRsaTime = measureExecutionTime(() => encryptWithFeistelAESRSA(inputMessage, publicKeyTestPath));
    const feistelAesRsaMemory = measureMemoryUsage(() => encryptWithFeistelAESRSA(inputMessage, publicKeyTestPath));
    console.log(`Tempo de execução da criptografia Feistel + AES + RSA: ${feistelAesRsaTime} ms`);
    console.log(`Consumo de memória da criptografia Feistel + AES + RSA: ${feistelAesRsaMemory} MB`);

    // Criptografia com AES
    const keyAes = crypto.randomBytes(32).toString('hex');
    const aesEncryptTime = measureExecutionTime(() => encryptWithAESOnly(inputMessage, keyAes));
    const aesEncryptMemory = measureMemoryUsage(() => encryptWithAESOnly(inputMessage, keyAes));
    console.log(`Tempo de execução da criptografia AES: ${aesEncryptTime} ms`);
    console.log(`Consumo de memória da criptografia AES: ${aesEncryptMemory} MB`);

    // Criptografar com Blowfish
    const keyBlowfish = CryptoJS.lib.WordArray.random(16).toString();
    const blowfishEncryptTime = measureExecutionTime(() => encryptWithBlowfish(inputMessage, keyBlowfish));
    const blowfishEncryptMemory = measureMemoryUsage(() => encryptWithBlowfish(inputMessage, keyBlowfish));
    console.log(`Tempo de execução da criptografia Blowfish: ${blowfishEncryptTime} ms`);
    console.log(`Consumo de memória da criptografia Blowfish: ${blowfishEncryptMemory} MB`);

    // Criptografar com DES
    const keyDes = CryptoJS.lib.WordArray.random(16).toString();
    const desEncryptTime = measureExecutionTime(() => encryptWithDES(inputMessage, keyDes));
    const desEncryptMemory = measureMemoryUsage(() => encryptWithDES(inputMessage, keyDes));
    console.log(`Tempo de execução da criptografia DES: ${desEncryptTime} ms`);
    console.log(`Consumo de memória da criptografia DES: ${desEncryptMemory} MB`);

    console.log("--------------------------------------- Resultados da descriptografia ---------------------------------------");
    // Descriptografar usando Feistel, AES e RSA
    const {encryptedMessage, encryptedSBox, encryptedAESKey} = encryptWithFeistelAESRSA(inputMessage, publicKeyTestPath);
    const feistelAesRsaDecryptTime =  measureExecutionTime(() => decryptWithFeistelAesRsa(encryptedMessage, encryptedSBox, encryptedAESKey));
    const feistelAesRsaDecryptMemory =  measureMemoryUsage(() => decryptWithFeistelAesRsa(encryptedMessage, encryptedSBox, encryptedAESKey));
    console.log(`Tempo de execução da descriptografia Feistel + AES + RSA: ${feistelAesRsaDecryptTime} ms`);
    console.log(`Consumo de memória da descriptografia Feistel + AES + RSA: ${feistelAesRsaDecryptMemory} MB`);

    // Descriptografar usando AES
    const messageAes = encryptWithAESOnly(inputMessage, keyAes);
    const aesDecryptTime = measureExecutionTime(() => decryptTestWithAes(messageAes, keyAes));
    const aesDecryptMemory = measureExecutionTime(() => decryptTestWithAes(messageAes, keyAes));
    console.log(`Tempo de execução da descriptografia AES: ${aesDecryptTime} ms`);
    console.log(`Consumo de memória da descriptografia AES: ${aesDecryptMemory} MB`);

    // Descriptografar usando Blowfish
    const messageBlowfish = encryptWithBlowfish(inputMessage, keyBlowfish);
    const blowfishDecryptTime = measureExecutionTime(() => decryptWithBlowfish(messageBlowfish, keyBlowfish));
    const blowfishDecryptMemory = measureExecutionTime(() => decryptWithBlowfish(messageBlowfish, keyBlowfish));
    console.log(`Tempo de execução da descriptografia Blowfish: ${blowfishDecryptTime} ms`);
    console.log(`Consumo de memória da descriptografia Blowfish: ${blowfishDecryptMemory} MB`);

    // Descriptografar usando DES
    const messageDes = encryptWithDES(inputMessage, keyDes);
    const desDecryptTime = measureExecutionTime(() => decryptWithDES(messageDes, keyDes));
    const desDecryptMemory = measureExecutionTime(() => decryptWithDES(messageDes, keyDes));
    console.log(`Tempo de execução da descriptografia DES: ${desDecryptTime} ms`);
    console.log(`Consumo de memória da descriptografia DES: ${desDecryptMemory} MB`);
}


// Função para medir o tempo de execução da criptografia/descriptografia
function measureExecutionTime(fn) {
    const start = process.hrtime.bigint();
    fn();
    const end = process.hrtime.bigint();
    return (end - start) / BigInt(1e6);
}

// Função para medir o uso de memória durante a execução da criptografia/descriptografia
function measureMemoryUsage(fn) {
    const start = process.memoryUsage().heapUsed;
    fn();
    const end = process.memoryUsage().heapUsed;
    return (end - start) / 1024 / 1024;
} 

// Função para criptografar a mensagem usando Feistel, AES e RSA
function encryptWithFeistelAESRSA(inputMessage,publicKeyTest) {
    // Gera uma sBox randomicamente
    const sBox = generateSboxRandomly();
    
    // Criptografa a mensagem com a cifra de Feistel
    const encryptedMessage = feistelCipherBuffer(Buffer.from(inputMessage), sBox, 16);
    
    // Gera uma chave AES
    const aesKey = crypto.randomBytes(32).toString('hex');
    
    // Criptografa o sBox com a chave AES
    const encryptedSBox = encryptWithAES(JSON.stringify(sBox), aesKey);
    
    // Criptografa a chave AES usando a chave pública RSA do destinatário (neste caso a própria máquina)
    const encryptedAESKey = encryptWithRSA(aesKey, publicKeyTest);
    
    return {
        encryptedMessage,
        encryptedSBox,
        encryptedAESKey
    };
}

// Função para criptografar a mensagem usando apenas AES
function encryptWithAESOnly(inputMessage, aesKey) {
    const ciphertext = CryptoJS.AES.encrypt(inputMessage, aesKey).toString();
    return ciphertext;
}

// Função para criptografar a mensagem usando apenas blowfish
function encryptWithBlowfish(inputMessage, keyBlowfish) {
    const encryptText = CryptoJS.Blowfish.encrypt(inputMessage, keyBlowfish).toString();
    return encryptText;
}

// Função para criptografar a mensagem usando apenas DES
function encryptWithDES(inputMessage, keyDes) {
    const encryptText = CryptoJS.DES.encrypt(inputMessage, keyDes).toString();
    return encryptText;
}

// Função para descriptografar usando Feistel + AES + RSA
function decryptWithFeistelAesRsa(textMessage, encryptedSBox, encryptedAESKey) {
    // Converte a mensagem criptografada de hexadecimal para buffer
    const encryptedMessage = Buffer.from(textMessage, 'hex');
    
    // Descriptografa a chave AES usando a chave privada RSA
    const passphrase = "";
    const aesKey = decryptWithRSA(encryptedAESKey, privateKeyTestPath, passphrase).toString('utf8');
    
    // Descriptografa o sBox usando a chave AES
    const decryptedSBox = decryptWithAES(encryptedSBox, aesKey);
    
    // Descriptografa a mensagem usando o sBox descriptografado
    const decryptedMessageBuffer = feistelDecipherBuffer(encryptedMessage, decryptedSBox, 16);
    
    return decryptedMessageBuffer;
}

// Função para descriptografar usando AES
function decryptTestWithAes(messageAes, keyAes) {
    const bytes = CryptoJS.AES.decrypt(messageAes, keyAes);
    return bytes.toString(CryptoJS.enc.Utf8);
}

// Função para descriptografar usando Blowfish
function decryptWithBlowfish(ciphertext, key) {
    const bytes = CryptoJS.Blowfish.decrypt(ciphertext, key);
    return bytes.toString(CryptoJS.enc.Utf8);
}

// Funçõa para descriptografar usando DES
function decryptWithDES(ciphertext, key) {
    const bytes = CryptoJS.DES.decrypt(ciphertext, key);
    return bytes.toString(CryptoJS.enc.Utf8);
}

function createKeys() {
    // Diretório onde as chaves serão armazenadas
    const keysDir = path.join(__dirname, 'keysTestEnvironment');
    
    // Verifica se a pasta 'keys' existe; caso contrário, cria
    if (!fs.existsSync(keysDir)) {
        fs.mkdirSync(keysDir);
    }
    
    // Gera par de chaves RSA
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
            type: 'pkcs1',
            format: 'pem'
        },
        privateKeyEncoding: {
            type: 'pkcs1',
            format: 'pem'
        }
    });
    
    // Caminhos completos para os arquivos de chaves
    publicKeyTestPath = path.join(keysDir, 'public_key.pem');
    privateKeyTestPath = path.join(keysDir, 'private_key.pem');
    
    // Salvar as chaves em arquivos
    fs.writeFileSync(publicKeyTestPath, publicKey);
    fs.writeFileSync(privateKeyTestPath, privateKey);
}

// --------------------------------------------------------------------- Testes de segurança ---------------------------------------------------------------------
// Função para executar testes de segurança
async function securityTests(){
    // Salva a mensagem informada pelo usuário
    const inputMessage = await getInputMessage();
    
    // Cria as chaves RSA locais para criptografar e descriptografar a mensagem
    createKeys();
    
    // Chama função que executa o teste de segurança
    processesSecurityTests(inputMessage);
}

// Executa testes de segurança
function processesSecurityTests(inputMessage) {

    // Cálculo da entropia usando AES
    const aesKey = crypto.randomBytes(32).toString('hex');
    const aesEncrypt = encryptWithAESOnly(inputMessage, aesKey);
    const aesEncryptBuffer = Buffer.from(aesEncrypt, 'base64');
    const aesEntropy = calculateEntropy(aesEncryptBuffer);
    console.log(`Entropia da mensagem criptografada: ${aesEntropy}`);

    // Cálculo da entropia usando Blowfish
    const blowfishKey = CryptoJS.lib.WordArray.random(16).toString();
    const blowfishEncrypt = encryptWithBlowfish(inputMessage, blowfishKey);
    const blowfishEncryptBuffer = Buffer.from(blowfishEncrypt, 'base64');
    const blowfishEntropy = calculateEntropy(blowfishEncryptBuffer);
    console.log(`Entropia da mensagem criptografada: ${blowfishEntropy}`);

    // Cálculo da entropia usando DES
    const desKey = CryptoJS.lib.WordArray.random(16).toString();
    const desEncrypt = encryptWithDES(inputMessage, desKey);
    const desEncryptBuffer = Buffer.from(desEncrypt, 'base64');
    const desEntropy = calculateEntropy(desEncryptBuffer);
    console.log(`Entropia da mensagem criptografada: ${desEntropy}`);
}

// Realiza cálculo de entropia
function calculateEntropy(encryptedBuffer) {
    const histogram = {};

    for (const byte of encryptedBuffer) {
        histogram[byte] = (histogram[byte] || 0) + 1;
    }

    const totalBytes = encryptedBuffer.length;
    let entropyValue = 0;

    // Calcula a entropia de Shannon
    for (const count of Object.values(histogram)) {
        const probability = count / totalBytes;
        entropyValue -= probability * Math.log2(probability);
    }

    return entropyValue;
}

// ----------------------------------------------------------------------------- Função Principal -----------------------------------------------------------------------------
// Chamadas principais para as funções de criptografia, descriptografia e ambiente de testes
(async () => {
    console.log("Escolha uma opção: ");
    console.log("1. Criptografar uma mensagem");
    console.log("2. Descriptografar uma mensagem");
    console.log("3. Ambiente de testes");

    const option = await new Promise((resolve) => {
        readline.question("Opção: ", (option) => resolve(option.trim()));
    });

    if (option === '1') {
        await encrypt();
    } else if (option === '2') {
        await decrypt();
    } else if (option === '3') {
        await testEnvironment();
    } else {
        console.log("Opção inválida!");
    }
    readline.close();
})();