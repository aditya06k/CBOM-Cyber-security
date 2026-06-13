"""Machine learning classifier for cryptographic asset detection."""

import random
import re
import string

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

CLASSES = ["quantum_vulnerable", "classically_weak", "quantum_safe", "unknown"]

_RANDOM = random.Random(42)


def _rand_name(prefix: str = "val") -> str:
    suffix = "".join(_RANDOM.choices(string.ascii_lowercase, k=5))
    return f"{prefix}_{suffix}"


def _format_template(template: str, **overrides: str) -> str:
    fields = set(re.findall(r"\{([a-z_]+)\}", template)) - set(overrides)
    values = {field: _rand_name(field) for field in fields}
    values.update(overrides)
    return template.format(**values)


def _from_templates(templates: list[str], count: int) -> list[str]:
    return [_format_template(templates[i % len(templates)]) for i in range(count)]


def _quantum_vulnerable_snippets(count: int) -> list[str]:
    templates = [
        (
            "from Crypto.PublicKey import RSA\n"
            "{key} = RSA.generate({bits})\n"
            "{cipher} = PKCS1_OAEP.new({key}.publickey())\n"
            "{out} = {cipher}.encrypt({data}.encode())\n"
            "return {out}"
        ),
        (
            "import rsa\n"
            "({pub}, {priv}) = rsa.newkeys({bits})\n"
            "{msg} = b'sensitive payload'\n"
            "{sig} = rsa.sign({msg}, {priv}, 'SHA-256')\n"
            "rsa.verify({msg}, {sig}, {pub})"
        ),
        (
            "from cryptography.hazmat.primitives.asymmetric import ec\n"
            "{priv} = ec.generate_private_key(ec.SECP256R1())\n"
            "{signer} = {priv}.signer(ec.ECDSA(hashes.SHA256()))\n"
            "{signer}.update({payload})\n"
            "{signature} = {signer}.finalize()"
        ),
        (
            "from nacl.bindings import crypto_sign_keypair\n"
            "{pk}, {sk} = crypto_sign_keypair()\n"
            "{signed} = crypto_sign({message}, {sk})\n"
            "crypto_sign_open({signed}, {pk})\n"
            "assert len({signed}) > 0"
        ),
        (
            "from cryptography.hazmat.primitives.asymmetric import x25519\n"
            "{priv} = x25519.X25519PrivateKey.generate()\n"
            "{pub} = {priv}.public_key()\n"
            "{shared} = {priv}.exchange({peer}.public_key())\n"
            "derive_session_key({shared})"
        ),
        (
            "from Crypto.PublicKey import DSA\n"
            "{key} = DSA.generate({bits})\n"
            "{h} = SHA256.new({data}.encode())\n"
            "{sig} = DSS.new({key}, 'fips-186-3').sign({h})\n"
            "verify_dsa_signature({sig})"
        ),
        (
            "openssl genrsa -out {pem} {bits}\n"
            "openssl rsa -in {pem} -pubout -out {pub_pem}\n"
            "rsautl -encrypt -inkey {pub_pem} -in {plain}\n"
            "store_ciphertext({out})\n"
            "log_key_usage('RSA')"
        ),
        (
            "const {key} = crypto.createPrivateKey('rsa', {bits});\n"
            "const {enc} = crypto.publicEncrypt({key}.export(), {buf});\n"
            "sendSecure({enc});\n"
            "auditTrail('ecdsa-handshake');\n"
            "return {enc};"
        ),
        (
            "using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.prime256v1);\n"
            "var {hash} = SHA256.HashData({input});\n"
            "var {sig} = ecdsa.SignHash({hash});\n"
            "ValidatePrime256Signature({sig});\n"
            "return {sig};"
        ),
        (
            "dh = DiffieHellman({group})\n"
            "{secret} = dh.generate_private_key()\n"
            "{shared} = dh.exchange({peer}.public_key)\n"
            "session = HKDF({shared}, salt={salt})\n"
            "return session"
        ),
    ]

    bits_choices = [1024, 2048, 3072, 4096]
    return [
        _format_template(
            templates[i % len(templates)],
            bits=str(bits_choices[i % len(bits_choices)]),
        )
        for i in range(count)
    ]


def _classically_weak_snippets(count: int) -> list[str]:
    templates = [
        (
            "import hashlib\n"
            "{data} = open({path}).read()\n"
            "{digest} = hashlib.md5({data}.encode()).hexdigest()\n"
            "cache[{digest}] = {data}\n"
            "print({digest})"
        ),
        (
            "from hashlib import sha1\n"
            "{token} = sha1({secret}.encode()).hexdigest()\n"
            "session_store.save({token})\n"
            "return {token}\n"
            "# legacy auth token"
        ),
        (
            "from Crypto.Cipher import DES\n"
            "{key} = b'8bytekey'\n"
            "{cipher} = DES.new({key}, DES.MODE_ECB)\n"
            "{out} = {cipher}.encrypt(pad({block}))\n"
            "write_blob({out})"
        ),
        (
            "cipher = DES3.new({key}, DES3.MODE_CBC, iv={iv})\n"
            "{ct} = cipher.encrypt({plaintext})\n"
            "upload({ct})\n"
            "logger.info('3des upload')\n"
            "return {ct}"
        ),
        (
            "from Crypto.Hash import MD5\n"
            "{h} = MD5.new()\n"
            "{h}.update({chunk})\n"
            "checksum = {h}.hexdigest()\n"
            "assert checksum"
        ),
        (
            "rc4 = ARC4.new({key})\n"
            "{stream} = rc4.encrypt({payload})\n"
            "socket.send({stream})\n"
            "metrics.increment('rc4')\n"
            "return {stream}"
        ),
        (
            "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\n"
            "algo = algorithms.AES({key})\n"
            "mode = modes.ECB()\n"
            "encryptor = Cipher(algo, mode).encryptor()\n"
            "{out} = encryptor.update({data})"
        ),
        (
            "const {hash} = crypto.createHash('md5');\n"
            "{hash}.update({input});\n"
            "const {digest} = {hash}.digest('hex');\n"
            "res.send({{ checksum: {digest} }});\n"
            "return;"
        ),
        (
            "using var sha1 = SHA1.Create();\n"
            "byte[] {hash} = sha1.ComputeHash({bytes});\n"
            "File.WriteAllBytes({path}, {hash});\n"
            "Console.WriteLine(Convert.ToHexString({hash}));\n"
            "return {hash};"
        ),
        (
            "bf = Blowfish.new({key})\n"
            "{ct} = bf.encrypt({msg})\n"
            "store_legacy({ct})\n"
            "rotate_weak_keys()\n"
            "return {ct}"
        ),
    ]

    return _from_templates(templates, count)


def _quantum_safe_snippets(count: int) -> list[str]:
    templates = [
        (
            "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
            "{key} = AESGCM.generate_key(bit_length=256)\n"
            "{aes} = AESGCM({key})\n"
            "{nonce} = os.urandom(12)\n"
            "{ct} = {aes}.encrypt({nonce}, {data}, None)\n"
            "return {nonce} + {ct}"
        ),
        (
            "import hashlib\n"
            "{payload} = json.dumps({record}).encode()\n"
            "{digest} = hashlib.sha256({payload}).hexdigest()\n"
            "audit_log[{digest}] = {record}\n"
            "return {digest}"
        ),
        (
            "from nacl.secret import SecretBox\n"
            "{key} = SecretBox.generate_key()\n"
            "{box} = SecretBox({key})\n"
            "{encrypted} = {box}.encrypt({message})\n"
            "persist({encrypted})"
        ),
        (
            "from Crypto.Cipher import ChaCha20\n"
            "{key} = get_random_bytes(32)\n"
            "{cipher} = ChaCha20.new(key={key})\n"
            "{ct} = {cipher}.encrypt({plaintext})\n"
            "transmit({cipher}.nonce + {ct})"
        ),
        (
            "from cryptography.hazmat.primitives import hashes\n"
            "{h} = hashes.Hash(hashes.SHA3_256())\n"
            "{h}.update({chunk})\n"
            "{out} = {h}.finalize()\n"
            "store_hash({out})"
        ),
        (
            "kem = ML_KEM_768()\n"
            "{pk}, {sk} = kem.generate_keypair()\n"
            "{ct}, {shared} = kem.encap({pk})\n"
            "{secret} = kem.decap({ct}, {sk})\n"
            "assert {shared} == {secret}"
        ),
        (
            "sig = ML_DSA_65.generate()\n"
            "{message} = canonicalize({payload})\n"
            "{signed} = sig.sign({message})\n"
            "verify_pqc({signed}, {message})\n"
            "archive({signed})"
        ),
        (
            "params = Kyber768()\n"
            "{pk}, {sk} = params.keygen()\n"
            "{ciphertext}, {shared} = params.enc({pk})\n"
            "{key} = params.dec({ciphertext}, {sk})\n"
            "derive_aes_gcm_key({key})"
        ),
        (
            "dilithium = Dilithium2()\n"
            "{pk}, {sk} = dilithium.keypair()\n"
            "{sig} = dilithium.sign({sk}, {msg})\n"
            "dilithium.verify({pk}, {msg}, {sig})\n"
            "return {sig}"
        ),
        (
            "const {cipher} = crypto.createCipheriv('aes-256-gcm', {key}, {iv});\n"
            "let {encrypted} = {cipher}.update({text}, 'utf8', 'hex');\n"
            "{encrypted} += {cipher}.final('hex');\n"
            "const {tag} = {cipher}.getAuthTag();\n"
            "return {{ {encrypted}, {tag} }};"
        ),
    ]

    return _from_templates(templates, count)


def _unknown_snippets(count: int) -> list[str]:
    templates = [
        (
            "def {func}({items}):\n"
            "    {total} = 0\n"
            "    for {item} in {items}:\n"
            "        {total} += {item}\n"
            "    return {total}"
        ),
        (
            "{name} = [__NUM_LIST__]\n"
            "for {idx} in range(len({name})):\n"
            "    print({name}[{idx}])\n"
            "print('done')\n"
            "# batch summary"
        ),
        (
            "import math\n"
            "{radius} = float(input('radius: '))\n"
            "{area} = math.pi * {radius} ** 2\n"
            "print(f'area={{area:.2f}}')\n"
            "save_metric({area})"
        ),
        (
            "async function {handler}({req}, {res}) {{\n"
            "  const {rows} = await db.query('SELECT * FROM users');\n"
            "  {res}.json({{ data: {rows} }});\n"
            "  return {rows}.length;\n"
            "}}"
        ),
        (
            "public static int {method}(int[] {nums}) {{\n"
            "    int {sum} = 0;\n"
            "    foreach (var {n} in {nums}) {{\n"
            "        {sum} += {n};\n"
            "    }}\n"
            "    return {sum};\n"
            "}}"
        ),
        (
            "SELECT {col}, COUNT(*) AS {cnt}\n"
            "FROM {table}\n"
            "GROUP BY {col}\n"
            "HAVING COUNT(*) > 1\n"
            "ORDER BY {cnt} DESC;"
        ),
        (
            "{config} = read_yaml({path})\n"
            "{timeout} = {config}.get('timeout', 30)\n"
            "logger.debug('timeout=%s', {timeout})\n"
            "scheduler.run(every={timeout})\n"
            "return {timeout}"
        ),
        (
            "const {result} = {values}.map(({x}) => {x} * 2);\n"
            "console.log({result}.join(', '));\n"
            "export default {result};\n"
            "// transform pipeline\n"
            "return {result};"
        ),
        (
            "class {cls}:\n"
            "    def __init__(self, {label}):\n"
            "        self.{label} = {label}\n"
            "    def describe(self):\n"
            "        return f'{{self.{label}}}'"
        ),
        (
            "fn {func}({input}: &str) -> usize {{\n"
            "    let mut {count} = 0;\n"
            "    for {ch} in {input}.chars() {{\n"
            "        if {ch}.is_alphanumeric() {{ {count} += 1; }}\n"
            "    }}\n"
            "    {count}\n"
            "}}"
        ),
    ]

    snippets = _from_templates(templates, count)
    return [
        snippet.replace(
            "__NUM_LIST__",
            ", ".join(str(_RANDOM.randint(1, 99)) for _ in range(4)),
        )
        for snippet in snippets
    ]


def generate_training_data() -> tuple[list[str], list[str]]:
    """Generate 80 synthetic 5-line snippets per class (320 total)."""
    texts: list[str] = []
    labels: list[str] = []

    generators = {
        "quantum_vulnerable": _quantum_vulnerable_snippets,
        "classically_weak": _classically_weak_snippets,
        "quantum_safe": _quantum_safe_snippets,
        "unknown": _unknown_snippets,
    }

    for label in CLASSES:
        snippets = generators[label](80)
        texts.extend(snippets)
        labels.extend([label] * len(snippets))

    return texts, labels


def train_model() -> Pipeline:
    """Train and return a TF-IDF + Logistic Regression pipeline."""
    texts, labels = generate_training_data()
    pipeline = Pipeline(
        [
            ("tfidf", TfidfVectorizer(ngram_range=(1, 2), max_features=5000)),
            ("clf", LogisticRegression(max_iter=1000)),
        ]
    )
    pipeline.fit(texts, labels)
    return pipeline


def classify_snippet(model: Pipeline, snippet: str) -> dict:
    """Classify a code snippet with confidence thresholding."""
    probabilities = model.predict_proba([snippet])[0]
    classes = list(model.classes_)
    best_index = int(probabilities.argmax())
    predicted = str(classes[best_index])
    confidence = float(probabilities[best_index])

    if predicted != "unknown" and confidence > 0.75:
        return {"classification": predicted, "confidence": confidence}

    unknown_index = classes.index("unknown")
    return {
        "classification": "unknown",
        "confidence": float(probabilities[unknown_index]),
    }


MODEL = train_model()
