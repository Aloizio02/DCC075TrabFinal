const crypto = require('crypto');

const readline = require('readline').createInterface({
    input: process.stdin,
    output: process.stdout
});

// ---------------------------------------------------------------- Funções responsáveis pela criptografia da mensagem ----------------------------------------------------------------
// ---------------------------------------------------------------- Cifra de Feistel -----------------------------------------------------------
// Chamada de funções para aplicação da criptografia da mensagem de entrada informada pelo usuário
async function encrypt() {
    const inputMessage = await getInputString();
    readline.close();
    const encryptedString = feistelCipher(inputMessage, 16);
    console.log("Entrada: ", inputMessage);
    console.log("Saída: ", Buffer.from(encryptedString, 'utf16le').toString('hex')); // Codifica para hex para visualização
}

// Recebe mensagem de entrada fornecida pelo usuário
async function getInputString() {
    return new Promise((resolve, reject) => {
        readline.question("Informe uma mensagem de entrada: ", (auxWord) => {
            auxWord = auxWord.replace(/\s+/g, '');
            if (auxWord) {
                resolve(auxWord);
            } else {
                console.log("Entrada inválida! Tente novamente. \n");
                getInputString();
            }
        });
    });
}

// Aplica o algoritmo de feistel
function feistelCipher(input, rounds) {
    const sBox = generateSboxRandomly();

    function feistel(input, rounds) {
        let left = input.charCodeAt(0);
        let right = input.charCodeAt(1);

        for (let i = 0; i < rounds; i++) {
            const temp = right;
            const row = right & 0x0F;
            const col = (right >> 4) & 0x0F;
            right = left ^ sBox[row][col];
            left = temp;
        }

        return String.fromCharCode(right) + String.fromCharCode(left);
    }

    let output = '';
    let i = 0;
    while (i < input.length) {
        if (i + 1 < input.length) {
            output += feistel(input.substr(i, 2), rounds);
        } else {
            let carac = input[i].charCodeAt(0);
            for (let j = 0; j < rounds; j++) {
                const row = carac & 0x0F;
                const col = (carac >> 4) & 0x0F;
                carac = carac ^ sBox[row][col];
            }
            output += String.fromCharCode(carac);
        }
        i += 2;
    }

    return output;
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
        console.log("1. Criptografar uma mensagem");
        console.log("2. Decriptar uma mensagem");
        console.log("3. Realizar testes de execucao");
        console.log("4. Sair");

        readline.question("Favor informar o numero da opcao desejada: ", (option) => {
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