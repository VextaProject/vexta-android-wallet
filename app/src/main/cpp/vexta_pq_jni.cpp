#include <jni.h>

#include <array>
#include <cstdint>
#include <vector>

#include "pq/pq.h"
#include <randomx.h>
#include <mutex>

namespace {

jbyteArray to_jbyte_array(
    JNIEnv* env,
    const uint8_t* data,
    size_t size)
{
    jbyteArray result =
        env->NewByteArray(static_cast<jsize>(size));

    if (result == nullptr) {
        return nullptr;
    }

    env->SetByteArrayRegion(
        result,
        0,
        static_cast<jsize>(size),
        reinterpret_cast<const jbyte*>(data)
    );

    return result;
}

bool copy_seed(
    JNIEnv* env,
    jbyteArray seed_array,
    std::array<uint8_t, 64>& seed)
{
    if (seed_array == nullptr ||
        env->GetArrayLength(seed_array) != 64) {
        return false;
    }

    env->GetByteArrayRegion(
        seed_array,
        0,
        64,
        reinterpret_cast<jbyte*>(seed.data())
    );

    return !env->ExceptionCheck();
}

} // namespace

extern "C"
JNIEXPORT jstring JNICALL
Java_org_vextaproject_wallet_VextaPQ_nativeVersion(
    JNIEnv* env,
    jobject)
{
    return env->NewStringUTF("Vexta PQ JNI 0.2");
}

extern "C"
JNIEXPORT jobjectArray JNICALL
Java_org_vextaproject_wallet_VextaPQ_mldsaKeypairFromSeed(
    JNIEnv* env,
    jobject,
    jbyteArray seed_array)
{
    std::array<uint8_t, 64> seed{};
    if (!copy_seed(env, seed_array, seed)) {
        return nullptr;
    }

    std::vector<uint8_t> public_key(
        pq::MLDSA65::PUBKEY_BYTES
    );
    std::vector<uint8_t> secret_key(
        pq::MLDSA65::SECKEY_BYTES
    );

    if (!pq::MLDSA65::keygen_from_seed(
            public_key.data(),
            secret_key.data(),
            seed.data())) {
        return nullptr;
    }

    jclass byte_array_class = env->FindClass("[B");
    jobjectArray result =
        env->NewObjectArray(2, byte_array_class, nullptr);

    if (result == nullptr) {
        return nullptr;
    }

    env->SetObjectArrayElement(
        result,
        0,
        to_jbyte_array(
            env,
            public_key.data(),
            public_key.size()
        )
    );

    env->SetObjectArrayElement(
        result,
        1,
        to_jbyte_array(
            env,
            secret_key.data(),
            secret_key.size()
        )
    );

    return result;
}

extern "C"
JNIEXPORT jobjectArray JNICALL
Java_org_vextaproject_wallet_VextaPQ_sphincsKeypairFromSeed(
    JNIEnv* env,
    jobject,
    jbyteArray seed_array)
{
    std::array<uint8_t, 64> seed{};
    if (!copy_seed(env, seed_array, seed)) {
        return nullptr;
    }

    std::vector<uint8_t> public_key(
        pq::SPHINCS128s::PUBKEY_BYTES
    );
    std::vector<uint8_t> secret_key(
        pq::SPHINCS128s::SECKEY_BYTES
    );

    if (!pq::SPHINCS128s::keygen_from_seed(
            public_key.data(),
            secret_key.data(),
            seed.data())) {
        return nullptr;
    }

    jclass byte_array_class = env->FindClass("[B");
    jobjectArray result =
        env->NewObjectArray(2, byte_array_class, nullptr);

    if (result == nullptr) {
        return nullptr;
    }

    env->SetObjectArrayElement(
        result,
        0,
        to_jbyte_array(
            env,
            public_key.data(),
            public_key.size()
        )
    );

    env->SetObjectArrayElement(
        result,
        1,
        to_jbyte_array(
            env,
            secret_key.data(),
            secret_key.size()
        )
    );

    return result;
}

namespace {

bool copy_byte_array(
    JNIEnv* env,
    jbyteArray input,
    std::vector<uint8_t>& output)
{
    if (input == nullptr) {
        return false;
    }

    const jsize length = env->GetArrayLength(input);

    output.resize(static_cast<size_t>(length));

    if (length > 0) {
        env->GetByteArrayRegion(
            input,
            0,
            length,
            reinterpret_cast<jbyte*>(output.data())
        );
    }

    return !env->ExceptionCheck();
}

} // namespace

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_org_vextaproject_wallet_VextaPQ_mldsaSign(
    JNIEnv* env,
    jobject,
    jbyteArray message_array,
    jbyteArray secret_key_array)
{
    std::vector<uint8_t> message;
    std::vector<uint8_t> secret_key;

    if (!copy_byte_array(env, message_array, message) ||
        !copy_byte_array(env, secret_key_array, secret_key) ||
        secret_key.size() != pq::MLDSA65::SECKEY_BYTES) {
        return nullptr;
    }

    std::vector<uint8_t> signature(
        pq::MLDSA65::SIG_BYTES
    );

    size_t signature_length = signature.size();

    if (!pq::MLDSA65::sign(
            signature.data(),
            &signature_length,
            message.data(),
            message.size(),
            secret_key.data())) {
        return nullptr;
    }

    signature.resize(signature_length);

    return to_jbyte_array(
        env,
        signature.data(),
        signature.size()
    );
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_org_vextaproject_wallet_VextaPQ_mldsaVerify(
    JNIEnv* env,
    jobject,
    jbyteArray signature_array,
    jbyteArray message_array,
    jbyteArray public_key_array)
{
    std::vector<uint8_t> signature;
    std::vector<uint8_t> message;
    std::vector<uint8_t> public_key;

    if (!copy_byte_array(env, signature_array, signature) ||
        !copy_byte_array(env, message_array, message) ||
        !copy_byte_array(env, public_key_array, public_key) ||
        public_key.size() != pq::MLDSA65::PUBKEY_BYTES) {
        return JNI_FALSE;
    }

    return pq::MLDSA65::verify(
        signature.data(),
        signature.size(),
        message.data(),
        message.size(),
        public_key.data()
    ) ? JNI_TRUE : JNI_FALSE;
}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_org_vextaproject_wallet_VextaPQ_sphincsSign(
    JNIEnv* env,
    jobject,
    jbyteArray message_array,
    jbyteArray secret_key_array)
{
    std::vector<uint8_t> message;
    std::vector<uint8_t> secret_key;

    if (!copy_byte_array(env, message_array, message) ||
        !copy_byte_array(env, secret_key_array, secret_key) ||
        secret_key.size() != pq::SPHINCS128s::SECKEY_BYTES) {
        return nullptr;
    }

    std::vector<uint8_t> signature(
        pq::SPHINCS128s::SIG_BYTES
    );

    size_t signature_length = signature.size();

    if (!pq::SPHINCS128s::sign(
            signature.data(),
            &signature_length,
            message.data(),
            message.size(),
            secret_key.data())) {
        return nullptr;
    }

    signature.resize(signature_length);

    return to_jbyte_array(
        env,
        signature.data(),
        signature.size()
    );
}

extern "C"
JNIEXPORT jboolean JNICALL
Java_org_vextaproject_wallet_VextaPQ_sphincsVerify(
    JNIEnv* env,
    jobject,
    jbyteArray signature_array,
    jbyteArray message_array,
    jbyteArray public_key_array)
{
    std::vector<uint8_t> signature;
    std::vector<uint8_t> message;
    std::vector<uint8_t> public_key;

    if (!copy_byte_array(env, signature_array, signature) ||
        !copy_byte_array(env, message_array, message) ||
        !copy_byte_array(env, public_key_array, public_key) ||
        public_key.size() != pq::SPHINCS128s::PUBKEY_BYTES) {
        return JNI_FALSE;
    }

    return pq::SPHINCS128s::verify(
        signature.data(),
        signature.size(),
        message.data(),
        message.size(),
        public_key.data()
    ) ? JNI_TRUE : JNI_FALSE;
}

namespace {

std::mutex g_randomx_mutex;
randomx_cache* g_randomx_cache = nullptr;
randomx_vm* g_randomx_vm = nullptr;
std::array<uint8_t, 32> g_randomx_seed{};
bool g_randomx_seed_initialized = false;

bool prepare_randomx_vm(
    const std::array<uint8_t, 32>& seed)
{
    if (
        g_randomx_vm != nullptr &&
        g_randomx_cache != nullptr &&
        g_randomx_seed_initialized &&
        g_randomx_seed == seed
    ) {
        return true;
    }

    if (g_randomx_vm != nullptr) {
        randomx_destroy_vm(g_randomx_vm);
        g_randomx_vm = nullptr;
    }

    if (g_randomx_cache != nullptr) {
        randomx_release_cache(g_randomx_cache);
        g_randomx_cache = nullptr;
    }

    g_randomx_seed_initialized = false;

    g_randomx_cache =
        randomx_alloc_cache(RANDOMX_FLAG_DEFAULT);

    if (g_randomx_cache == nullptr) {
        return false;
    }

    randomx_init_cache(
        g_randomx_cache,
        seed.data(),
        seed.size()
    );

    g_randomx_vm =
        randomx_create_vm(
            RANDOMX_FLAG_DEFAULT,
            g_randomx_cache,
            nullptr
        );

    if (g_randomx_vm == nullptr) {
        randomx_release_cache(g_randomx_cache);
        g_randomx_cache = nullptr;
        return false;
    }

    g_randomx_seed = seed;
    g_randomx_seed_initialized = true;

    return true;
}

} // namespace

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_org_vextaproject_wallet_VextaPQ_randomxHash(
    JNIEnv* env,
    jobject,
    jbyteArray header_array,
    jbyteArray seed_array)
{
    if (header_array == nullptr ||
        seed_array == nullptr ||
        env->GetArrayLength(header_array) != 80 ||
        env->GetArrayLength(seed_array) != 32) {
        return nullptr;
    }

    std::array<uint8_t, 80> header{};
    std::array<uint8_t, 32> seed{};
    std::array<uint8_t, 32> output{};

    env->GetByteArrayRegion(
        header_array,
        0,
        80,
        reinterpret_cast<jbyte*>(header.data())
    );

    if (env->ExceptionCheck()) {
        return nullptr;
    }

    env->GetByteArrayRegion(
        seed_array,
        0,
        32,
        reinterpret_cast<jbyte*>(seed.data())
    );

    if (env->ExceptionCheck()) {
        return nullptr;
    }

    {
        std::lock_guard<std::mutex> lock(g_randomx_mutex);

        if (!prepare_randomx_vm(seed)) {
            return nullptr;
        }

        randomx_calculate_hash(
            g_randomx_vm,
            header.data(),
            header.size(),
            output.data()
        );
    }

    return to_jbyte_array(
        env,
        output.data(),
        output.size()
    );
}
