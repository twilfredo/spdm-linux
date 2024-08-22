/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Public Key Signature Algorithm
 *
 * Copyright (c) 2023 Herbert Xu <herbert@gondor.apana.org.au>
 */
#ifndef _CRYPTO_SIG_H
#define _CRYPTO_SIG_H

#include <linux/crypto.h>

/**
 * struct crypto_sig - user-instantiated objects which encapsulate
 * algorithms and core processing logic
 *
 * @base:	Common crypto API algorithm data structure
 */
struct crypto_sig {
	struct crypto_tfm base;
};

/**
 * struct sig_alg - generic public key signature algorithm
 *
 * @sign:	Function performs a sign operation as defined by public key
 *		algorithm.
 * @verify:	Function performs a complete verify operation as defined by
 *		public key algorithm, returning verification status.
 * @set_pub_key: Function invokes the algorithm specific set public key
 *		function, which knows how to decode and interpret
 *		the BER encoded public key and parameters
 * @set_priv_key: Function invokes the algorithm specific set private key
 *		function, which knows how to decode and interpret
 *		the BER encoded private key and parameters
 * @max_size:	Function returns maximum key size
 * @init:	Initialize the cryptographic transformation object.
 *		This function is used to initialize the cryptographic
 *		transformation object. This function is called only once at
 *		the instantiation time, right after the transformation context
 *		was allocated. In case the cryptographic hardware has some
 *		special requirements which need to be handled by software, this
 *		function shall check for the precise requirement of the
 *		transformation and put any software fallbacks in place.
 * @exit:	Deinitialize the cryptographic transformation object. This is a
 *		counterpart to @init, used to remove various changes set in
 *		@init.
 *
 * @base:	Common crypto API algorithm data structure
 */
struct sig_alg {
	int (*sign)(struct crypto_sig *tfm,
		    const void *src, unsigned int slen,
		    void *dst, unsigned int dlen);
	int (*verify)(struct crypto_sig *tfm,
		      const void *src, unsigned int slen,
		      const void *digest, unsigned int dlen);
	int (*set_pub_key)(struct crypto_sig *tfm,
			   const void *key, unsigned int keylen);
	int (*set_priv_key)(struct crypto_sig *tfm,
			    const void *key, unsigned int keylen);
	unsigned int (*max_size)(struct crypto_sig *tfm);
	int (*init)(struct crypto_sig *tfm);
	void (*exit)(struct crypto_sig *tfm);

	struct crypto_alg base;
};

/**
 * DOC: Generic Public Key Signature API
 *
 * The Public Key Signature API is used with the algorithms of type
 * CRYPTO_ALG_TYPE_SIG (listed as type "sig" in /proc/crypto)
 */

/**
 * crypto_alloc_sig() - allocate signature tfm handle
 * @alg_name: is the cra_name / name or cra_driver_name / driver name of the
 *	      signing algorithm e.g. "ecdsa"
 * @type: specifies the type of the algorithm
 * @mask: specifies the mask for the algorithm
 *
 * Allocate a handle for public key signature algorithm. The returned struct
 * crypto_sig is the handle that is required for any subsequent
 * API invocation for signature operations.
 *
 * Return: allocated handle in case of success; IS_ERR() is true in case
 *	   of an error, PTR_ERR() returns the error code.
 */
struct crypto_sig *crypto_alloc_sig(const char *alg_name, u32 type, u32 mask);

static inline struct crypto_tfm *crypto_sig_tfm(struct crypto_sig *tfm)
{
	return &tfm->base;
}

static inline struct crypto_sig *__crypto_sig_tfm(struct crypto_tfm *tfm)
{
	return container_of(tfm, struct crypto_sig, base);
}

static inline struct sig_alg *__crypto_sig_alg(struct crypto_alg *alg)
{
	return container_of(alg, struct sig_alg, base);
}

static inline struct sig_alg *crypto_sig_alg(struct crypto_sig *tfm)
{
	return __crypto_sig_alg(crypto_sig_tfm(tfm)->__crt_alg);
}

/**
 * crypto_free_sig() - free signature tfm handle
 *
 * @tfm: signature tfm handle allocated with crypto_alloc_sig()
 *
 * If @tfm is a NULL or error pointer, this function does nothing.
 */
static inline void crypto_free_sig(struct crypto_sig *tfm)
{
	crypto_destroy_tfm(tfm, crypto_sig_tfm(tfm));
}

/**
 * crypto_sig_maxsize() - Get len for output buffer
 *
 * Function returns the dest buffer size required for a given key.
 * Function assumes that the key is already set in the transformation. If this
 * function is called without a setkey or with a failed setkey, you will end up
 * in a NULL dereference.
 *
 * @tfm:	signature tfm handle allocated with crypto_alloc_sig()
 */
int crypto_sig_maxsize(struct crypto_sig *tfm);

/**
 * crypto_sig_sign() - Invoke signing operation
 *
 * Function invokes the specific signing operation for a given algorithm
 *
 * @tfm:	signature tfm handle allocated with crypto_alloc_sig()
 * @src:	source buffer
 * @slen:	source length
 * @dst:	destination obuffer
 * @dlen:	destination length
 *
 * Return: zero on success; error code in case of error
 */
int crypto_sig_sign(struct crypto_sig *tfm,
		    const void *src, unsigned int slen,
		    void *dst, unsigned int dlen);

/**
 * crypto_sig_verify() - Invoke signature verification
 *
 * Function invokes the specific signature verification operation
 * for a given algorithm.
 *
 * @tfm:	signature tfm handle allocated with crypto_alloc_sig()
 * @src:	source buffer
 * @slen:	source length
 * @digest:	digest
 * @dlen:	digest length
 *
 * Return: zero on verification success; error code in case of error.
 */
int crypto_sig_verify(struct crypto_sig *tfm,
		      const void *src, unsigned int slen,
		      const void *digest, unsigned int dlen);

/**
 * crypto_sig_set_pubkey() - Invoke set public key operation
 *
 * Function invokes the algorithm specific set key function, which knows
 * how to decode and interpret the encoded key and parameters
 *
 * @tfm:	tfm handle
 * @key:	BER encoded public key, algo OID, paramlen, BER encoded
 *		parameters
 * @keylen:	length of the key (not including other data)
 *
 * Return: zero on success; error code in case of error
 */
int crypto_sig_set_pubkey(struct crypto_sig *tfm,
			  const void *key, unsigned int keylen);

/**
 * crypto_sig_set_privkey() - Invoke set private key operation
 *
 * Function invokes the algorithm specific set key function, which knows
 * how to decode and interpret the encoded key and parameters
 *
 * @tfm:	tfm handle
 * @key:	BER encoded private key, algo OID, paramlen, BER encoded
 *		parameters
 * @keylen:	length of the key (not including other data)
 *
 * Return: zero on success; error code in case of error
 */
int crypto_sig_set_privkey(struct crypto_sig *tfm,
			   const void *key, unsigned int keylen);
#endif
