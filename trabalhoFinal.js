const crypto = require('crypto');

const readline = require('readline').createInterface({
    input: process.stdin,
    output: process.stdout
});

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

// ---------------------------------------------- Cifra de Feistel ----------------------------------------------

// Aplica o algoritmo de feistel
function feistelCipher(input, rounds) {
    const sBox = generateSboxRandomly();

    function feistel(input, rounds) {
        let left = input.charCodeAt(0);
        let right = input.charCodeAt(1);

        for (let i = 0; i < rounds; i++) {
            const temp = right;
            const row = right & 0x1F;
            const col = (right >> 5) & 0x1F;
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
                const row = carac & 0x1F;
                const col = (carac >> 5) & 0x1F;
                carac = carac ^ sBox[row][col];
            }
            output += String.fromCharCode(carac);
        }
        i += 2;
    }

    return output;
}

// Gerar randomicamente a uma sBox (usando o módulo crypto do node.js)
function generateSboxRandomly() {
    let sBox = [];
    const mDimension = 32;
    const randomBytes = crypto.randomBytes(mDimension * mDimension * 2);
    for (let i = 0; i < mDimension * mDimension; i++) {
        const value = randomBytes.readUInt16BE(i * 2);
        sBox.push(value);
    }
    // Faz a transformação para uma matriz 32 x 32
    const matrix = [];
    for (let i = 0; i < mDimension; i++) {
        matrix.push(sBox.slice(i * mDimension, (i + 1) * mDimension));
    }
    return matrix;
}

// ---------------------------------------------- Função principal ----------------------------------------------

// Função principal que cria menu para o usuário escolher algumas opções no programa
async function main(){
    return new Promise;
}

// Chamada de funções para aplicação da criptografia da mensagem de entrada informada pelo usuário
async function encrypt() {
    const inputMessage = await getInputString();
    readline.close();
    const encryptedString = feistelCipher(inputMessage, 16);
    console.log("Entrada: ", inputMessage);
    console.log("Saída: ", Buffer.from(encryptedString, 'utf16le').toString('hex')); // Codifica para hex para visualização
}

// Chama a função principal
encrypt();