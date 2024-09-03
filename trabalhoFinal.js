const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const readline = require('readline').createInterface({
    input: process.stdin,
    output: process.stdout
});

// ---------------------------------------------- Cifra de Feistel para Arquivos ----------------------------------------------

// Chamada de funções para aplicação da criptografia do arquivo informado pelo usuário
async function encrypt() {
    const { directory, filename } = await getFilePath();
    readline.close();

    const inputFilePath = path.join(directory, filename);
    const outputFilePath = path.join(directory, 'arquivo_criptografado.dat');

    // Ler o arquivo em formato binário
    const inputBuffer = fs.readFileSync(inputFilePath);

    // Aplicar a cifra de Feistel no buffer de bytes
    const encryptedBuffer = feistelCipherBuffer(inputBuffer, 16);

    // Salvar o resultado criptografado em um novo arquivo
    fs.writeFileSync(outputFilePath, encryptedBuffer);

    console.log(`Arquivo criptografado salvo como: ${outputFilePath}`);
}

// Recebe o diretório e o nome do arquivo fornecidos pelo usuário
async function getFilePath() {
    return new Promise((resolve, reject) => {
        readline.question("Informe o diretório do arquivo: ", (directory) => {
            readline.question("Informe o nome do arquivo: ", (filename) => {
                if (directory && filename) {
                    resolve({ directory: directory.trim(), filename: filename.trim() });
                } else {
                    console.log("Entrada inválida! Tente novamente.\n");
                    getFilePath().then(resolve).catch(reject);
                }
            });
        });
    });
}

// Aplica o algoritmo de Feistel para um buffer de bytes
function feistelCipherBuffer(inputBuffer, rounds) {
    const sBox = generateSboxRandomly();

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

// --------------------------------------------------------------------------- Funções principais ---------------------------------------------------------------------------

// Função responsável pela criação do menu e retorno da opção escolhida pelo usuário
async function main() {
    return new Promise((resolve, reject) => {
        console.log("\n----- Menu -----");
        console.log("1. Criptografar um arquivo");
        console.log("2. Decriptar um arquivo");
        console.log("3. Realizar testes de execução");
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
                    resolve('test');
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
            console.log("Preciso implementar");
            readline.close();
            break;
        case 'test':
            console.log("Preciso implementar");
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