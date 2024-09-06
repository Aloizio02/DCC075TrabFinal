const crypto = require('crypto');
const fs = require('fs');
const CryptoJS = require('crypto-js');
const readline = require('readline').createInterface({
    input: process.stdin,
    output: process.stdout
});

// ---------------------------------------------- Etapa de criptografia ----------------------------------------------
// Função principal para a criptografia
async function encrypt() {
    // Gera as chaves RSA se ainda não existirem
    generateRSAKeys();

    // Salva a mensagem informada pelo usuário
    const inputMessage = await getInputMessage();

    // Gera uma sBox randomicamente
    const sBox = generateSboxRandomly();

    // Criptografa a mensagem com a cifra de Feistel
    const encryptedMessage = feistelCipherBuffer(Buffer.from(inputMessage), sBox, 16);
    console.log(`Mensagem criptografada: ${encryptedMessage.toString('hex')}`);

    // Gera uma chave AES
    const aesKey = crypto.randomBytes(32).toString('hex');
    const encryptedSBox = encryptWithAES(JSON.stringify(sBox), aesKey);

    // Criptografa a chave AES usando RSA
    const encryptedAESKey = encryptWithRSA(aesKey);

    // Salva o sBox criptografado e a chave AES criptografada
    fs.writeFileSync('encrypted_sbox.dat', encryptedSBox);
    fs.writeFileSync('encrypted_aes_key.dat', encryptedAESKey);

    console.log('sBox salvo em "encrypted_sbox.dat".');
    console.log('Chave AES salva em "encrypted_aes_key.dat".');
}

// Recebe uma mensagem de entrada fornecida pelo usuário
async function getInputMessage() {
    return new Promise((resolve, reject) => {
        readline.question("Informe uma mensagem para criptografar: ", (message) => {
            message = message.replace(/\s+/g, '');
            if (message) {
                resolve(message);
            } else {
                console.log("Entrada invalida! Tente novamente.\n");
                getInputMessage().then(resolve).catch(reject);
            }
        });
    });
}

// ---------------------------------------------- Primeira camada: Algoritmo de Feistel na mensagem ----------------------------------------------
// Aplica o algoritmo de Feistel para um buffer de bytes
function feistelCipherBuffer(inputBuffer, sBox, rounds) {
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
// Função para gerar as chaves RSA se elas não existirem
function generateRSAKeys() {
    const privateKeyPath = 'private.pem';
    const publicKeyPath = 'public.pem';

    // Verifica se as chaves já existem
    if (!fs.existsSync(privateKeyPath) || !fs.existsSync(publicKeyPath)) {
        console.log("Gerando chaves RSA...");

        // Gerar par de chaves RSA
        const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
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

        // Salvar chaves no sistema de arquivos
        fs.writeFileSync(privateKeyPath, privateKey);
        fs.writeFileSync(publicKeyPath, publicKey);

        console.log("Chaves RSA geradas e salvas em 'private.pem' e 'public.pem'.");
    } else {
        console.log("Chaves RSA já existem.");
    }
}

// Função para criptografar dados usando a chave pública RSA
function encryptWithRSA(data) {
    const publicKey = fs.readFileSync('public.pem', 'utf8');
    return crypto.publicEncrypt(publicKey, Buffer.from(data));
}

// Função para descriptografar dados usando a chave privada RSA
function decryptWithRSA(encryptedData) {
    const privateKey = fs.readFileSync('private.pem', 'utf8');
    return crypto.privateDecrypt(privateKey, encryptedData);
}

// ---------------------------------------------- Funções Principais ----------------------------------------------

// Função responsável pela criação do menu e retorno da opção escolhida pelo usuário
async function main() {
    return new Promise((resolve, reject) => {
        console.log("\n----- Menu -----");
        console.log("1. Criptografar uma mensagem");
        console.log("2. Decriptografar uma mensagem");
        console.log("3. Ambiente de testes");
        console.log("4. Sair");

        readline.question("Favor informar o número da opção desejada: ", (option) => {
            switch (option.trim()) {
                case '1':
                    resolve('encrypt');
                    break;
                case '2':
                    resolve('decrypt');
                    break;
                case '3':
                    resolve('testEnvironment');
                    break;
                case '4':
                    console.log("Saindo do programa.");
                    readline.close();
                    process.exit(0);
                default:
                    console.log("Opção inválida! Tente novamente.");
                    main().then(resolve).catch(reject);
                    break;
            }
        });
    });
}

// Função principal do programa
async function run() {
    const option = await main();
    switch (option) {
        case 'encrypt':
            await encrypt();
            break;
        case 'decrypt':
            console.log("Decrypt ainda não implementado.");
            break;
        case 'testEnvironment':
            console.log("Geração de relatórios não implementada.");
            readline.close();
            break;
        default:
            console.log("Erro inesperado.");
            readline.close();
            break;
    }
}

// Chama a função principal
run();