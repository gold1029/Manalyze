/*
    This file is part of Manalyze.

    Manalyze is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Manalyze is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Manalyze.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <string.h>
#include <sstream>

#include <boost/shared_ptr.hpp>
#include <boost/cstdint.hpp>

#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/asn1.h>
#include <openssl/err.h>

#include "plugin_framework/plugin_interface.h"

typedef std::vector<boost::uint8_t> bytes;
typedef boost::shared_ptr<PKCS7>    pPKCS7;
typedef boost::shared_ptr<BIO>      pBIO;

const std::string SPC_INDIRECT_DATA = "1.3.6.1.4.1.311.2.1.4";
const std::string SPC_PE_IMAGE_DATAOBJ = "1.3.6.1.4.1.311.2.1.15";
const std::string MD5_OID = "1.2.840.113549.2.5";
const std::string SHA1_OID = "1.3.14.3.2.26";

namespace plugin
{

// A simple struct describing the digest. The first member is the algorithm used (OID), and the second member is the digest.
struct AuthenticodeDigest
{
    std::string algorithm;
    bytes digest;
};

/**
 *  @brief  Returns the contents of an OpenSSL BIO as a string.
 *
 *  @param  pBIO bio The BIO to convert.
 *
 *  @return A string containing the contents of the BIO.
 */
std::string bio_to_string(pBIO bio)
{
    BUF_MEM* buf = nullptr; // The memory pointed by this is freed with the BIO.
    BIO_get_mem_ptr(bio.get(), &buf);
    if (buf == nullptr || buf->length == 0)
    {
        PRINT_WARNING << "[plugin_authenticode] Tried to convert an empty BIO." << std::endl;
        return "";
    }
    return std::string(buf->data, buf->length);
}

// ----------------------------------------------------------------------------
 
/**
 *  @brief  Returns the contents of an OpenSSL X509_NAME as a string.
 *
 *  @param  X509_NAME* name A pointer to the X509_NAME to convert.
 *
 *  @return A string containing the contents of the X509_NAME.
 */
std::string X509_NAME_to_string(X509_NAME* name)
{
    pBIO bio_out(BIO_new(BIO_s_mem()), BIO_free);
    X509_NAME_print_ex(bio_out.get(), name, 0, 0);
    return bio_to_string(bio_out);
}

// ----------------------------------------------------------------------------

/**
 *  @brief  Converts an hexadecimal OID into its string representation.
 *
 *  @param  const bytes& in The raw OID bytes.
 *
 *  @return A string containing the OID in its (somewhat) human-readable form.
 */
std::string OID_to_string(const bytes& in)
{
    if (in.size() == 0) {
        return "";
    }
    std::stringstream ss;
    
    int b = in[0] % 40;
    int a = (in[0] - b) / 40;
    ss << a << "." << b;

    for (unsigned int i = 1 ; i < in.size() ; ++i)
    {
        ss << ".";
        if (in[i] < 128) {
            ss << static_cast<int>(in[i]); // Do not interpret as a char. 
        }
        else 
        {
            if (i+1 >= in.size()) // Don't read outside of the bounds. 
            {
                    PRINT_WARNING << "[plugin_authenticode] Tried to convert a malformed OID!" << std::endl;
                    return "";
            }
            ss << static_cast<int>((in[i]-128)*128 + in[i+1]);
            ++i; 
        }
    }
    return ss.str();
}

// ----------------------------------------------------------------------------
    
/**
 *  @brief  This function asserts that a PKCS7 object has a valid structure
 *          before attempting any operations on it.
 *
 *  @param  pPKCS7 p The PKCS7 object to verify.
 *
 *  @return Whether the object can be used safely to verify an Authenticode signature.
 */
bool check_pkcs_sanity(pPKCS7 p)
{
    if (p == nullptr)
    {
        PRINT_WARNING << "[plugin_authenticode] Error reading the PKCS7 certificate." << std::endl;
        return false;
    }

    if (!PKCS7_type_is_signed(p.get()))
    {
        PRINT_WARNING << "[plugin_authenticode] The PKCS7 structure is not signed!" << std::endl;
        return false;
    }

    // The SpcIndirectDataContent structure of the signature cannot be accessed directly
    // with OpenSSL's API. Retrieve the information manually.
    if (p->d.sign == nullptr || 
        p->d.sign->contents == nullptr ||
        p->d.sign->contents->type == nullptr ||
        p->d.sign->contents->type->data == nullptr ||
        p->d.sign->contents->d.other == nullptr ||
        p->d.sign->contents->d.other->value.asn1_string == nullptr)
    {
        PRINT_WARNING << "[plugin_authenticode] Unable to access the "
                            "SpcIndirectDataContent structure." << std::endl;
        return false;
    }

    // Assert that the data indeed points to a SpcIndirectDataContent object by checking the OID.
    bytes oid(p->d.sign->contents->type->data, 
                p->d.sign->contents->type->data + p->d.sign->contents->type->length);
    if (OID_to_string(oid) != SPC_INDIRECT_DATA)
    {
        PRINT_WARNING << "[plugin_authenticode] Unable to access the "
                            "SpcIndirectDataContent structure." << std::endl;
        return false;
    }

    return true;
}

// ----------------------------------------------------------------------------

/**
 *  @brief  Helper function designed to read ASN1 objects.
 *
 *  This function is useful to read objects of an expected type. Its main use is
 *  to avoid code duplication around error messages.
 *
 *  @param  const unsigned char** data A pointer to the ASN1 string to read.
 *          It will be updated to point to the next object in the string. 
 *  @param  long max_length The maximum number of bytes to read.
 *  @param  const std::string& expected The object type expected (i.e. "SEQUENCE").
 *          This argument is given as a string for code readability.
 *  @param  const std::string& structure_name The name of the object read (for error messages only).
 *
 *  @return The size of the object read. The data pointer will be updated to point to it.
 */
long asn1_read(const unsigned char** data,
               long max_length,
               const std::string& expected,
               const std::string& object_name)
{
    int tag = 0, xclass = 0;
    long size = 0;

    ASN1_get_object(data, &size, &tag, &xclass, max_length); // Return value ignored. Who knows what this function returns?
    std::string tag_s = ASN1_tag2str(tag);
    if (tag_s != expected)
    {
        PRINT_WARNING << "[plugin_authenticode] The " << object_name << " ASN1 string is malformed!" << std::endl;
        PRINT_WARNING << "(Expected " << expected << ", but got " << tag_s << " instead.)" << std::endl;
        return 0;
    }
    return size;
}

// ----------------------------------------------------------------------------

/**
 *  @brief  This function parses an ASN1 SpcIndirectDataContent object.
 *
 *  The SpcIndirectDataContent contains the digest and algorithm of the authenticode
 *  hash generated for the PE. This function's role is to go down the ASN1 rabbit hole
 *  and retreive this information so that the digest can be computed independently and
 *  verified against the information contained in this signature.
 *
 *  @param  ASN1_STRING* asn1 The ASN1 string pointing to the SpcIndirectDataContent object.
 *  @param  AuthenticodeDigest& digest The structure into which the digest information will be put.
 *
 *  @return Whether the ASN1 was parsed successfully.
 */
bool parse_spc_asn1(ASN1_STRING* asn1, AuthenticodeDigest& digest)
{    
    const unsigned char* asn1_data = asn1->data;
    bytes buffer;

    // Start at the SpcIndirectDataContent..
    long size = asn1_read(&asn1_data, asn1->length, "SEQUENCE", "SpcIndirectDataContent");
    if (size == 0) {
        return false;
    }
    // Read the SpcAttributeTypeAndOptionalValue.
    size = asn1_read(&asn1_data, asn1->length, "SEQUENCE", "SpcAttributeTypeAndOptionalValue");
    if (size == 0) {
        return false;
    }
    // Read SpcAttributeTypeAndOptionalValue->type
    size = asn1_read(&asn1_data, asn1->length, "OBJECT", "type");
    if (size == 0) {
        return false;
    }
    // Assert that the type read has the expected OID.
    buffer.assign(asn1_data, asn1_data + size);
    if(OID_to_string(buffer) != SPC_PE_IMAGE_DATAOBJ)
    {
        PRINT_WARNING << "[plugin_authenticode] The SpcAttributeTypeAndOptionalValue has an invalid type!" << std::endl;
        return false;
    }
    asn1_data += size; // Skip over the OID.
    // Read SpcAttributeTypeAndOptionalValue->value (SpcPeImageData)
    size = asn1_read(&asn1_data, asn1->length, "SEQUENCE", "SpcPeImageData");
    if (size == 0) {
        return false;
    }
    asn1_data += size; // Skip the structure.

    // Read the DigestInfo.
    size = asn1_read(&asn1_data, asn1->length, "SEQUENCE", "DigestInfo");
    if (size == 0) {
        return false;
    }
    // Read DigestInfo->AlgorithmIdentifier
    size = asn1_read(&asn1_data, asn1->length, "SEQUENCE", "AlgorithmIdentifier");
    if (size == 0) {
        return false;
    }
    // Read DigestInfo->AlgorithmIdentifier->algorithm)
    size = asn1_read(&asn1_data, asn1->length, "OBJECT", "algorithm");
    if (size == 0) {
        return false;
    }
    buffer.assign(asn1_data, asn1_data + size);
    digest.algorithm = OID_to_string(buffer);
    asn1_data += size;
    // Read and skip DigestInfo->AlgorithmIdentifier->parameters
    size = asn1_read(&asn1_data, asn1->length, "NULL", "parameters");
    // Read the digest.
    size = asn1_read(&asn1_data, asn1->length, "OCTET STRING", "digest");
    if (size == 0) {
        return false;
    }
    digest.digest.assign(asn1_data, asn1_data + size);

    return true;
}

// ----------------------------------------------------------------------------

/**
 *  @brief  Shorthand function used to get the CN part of an X509_NAME.
 *
 *  X509_NAMEs have the following format after having been converted to a
 *  string: "C=US, O=Thawte, Inc., CN=Thawte Code Signing CA - G2". This
 *  function simply returns the CN part.
 *
 *  @param  const std::string& x509_name The string containing the certificate
 *          information.
 *
 *  @return A string containing the CN of the X509_NAME. 
 */
std::string get_CN(const std::string& x509_name)
{
    auto pos = x509_name.find("CN=");
    if (pos == std::string::npos)
    {
        PRINT_WARNING << "[plugin_authenticode] Trying to obtain the Common Name of a malformed string! (" 
            << x509_name << ")" << std::endl;
        return "";
    }
    
    try
    {
        // Skip "CN=" and go until the next '/' or the end of the string.
        // Some CNs look like this: CN=Someone/emailAddress=address@provider.com
        return x509_name.substr(pos + 3, x509_name.find_first_of("/,", pos + 3) - pos - 3);
    }
    catch (std::out_of_range&)
    {
        PRINT_WARNING << "[plugin_authenticode] Trying to obtain the Common Name of a malformed string! (" 
            << x509_name << ")" << std::endl;
        return "";
    }
}

// ----------------------------------------------------------------------------

/**
 *  @brief  This function navigates through the digital signature's
 *          certificate chain to retreive the successive common names.
 *
 *  @param  pPKCS7 p The PKCS7 object containing the digital signature.
 *  @param  pResult res The result in which the names should be added.
 */
void add_certificate_information(pPKCS7 p, pResult res)
{
    STACK_OF(X509)* signers = PKCS7_get0_signers(p.get(), nullptr, 0);
    if (signers == nullptr)
    {
        PRINT_WARNING << "[plugin_authenticode] Could not obtain the certificate signers." << std::endl;
        return;
    }

    if (sk_X509_num(signers) != 1)
    {
        PRINT_WARNING << "[plugin_authenticode] Authenticode signature should contain a single SignerInfo structure, but " 
                      << sk_X509_num(signers) << " were found." << std::endl;
    }

    for (int i = 0 ; i < sk_X509_num(signers) ; ++i)
    {
        // X509_NAMEs don't need to be freed.
        X509_NAME* issuer = X509_get_issuer_name(sk_X509_value(signers, i));
        X509_NAME* subject = X509_get_subject_name(sk_X509_value(signers, i));
        std::string issuer_str = X509_NAME_to_string(issuer);
        std::string subject_str = X509_NAME_to_string(subject);
        res->add_information("Signer: " + get_CN(subject_str) + ".");
        res->add_information("Issuer: " + get_CN(issuer_str) + ".");
    }
    
    sk_X509_free(signers);
}

// ----------------------------------------------------------------------------

bool verify_signature(const mana::PE& pe, pPKCS7 signature, AuthenticodeDigest& digest, pResult res)
{
    /*if (!EVP_add_digest(EVP_md5()) || !EVP_add_digest(EVP_sha1()) || !EVP_add_digest(EVP_sha256()) ||
        !EVP_add_digest(EVP_sha384()) || !EVP_add_digest(EVP_sha512()) || 
        !EVP_add_digest_alias(SN_sha1WithRSAEncryption, SN_sha1WithRSA))
    {
        PRINT_ERROR << "[plugin_authenticode] Could not initialize OpenSSL digests." << std::endl;
        return false;
    }*/

    // Put the data to verify inside a BIO. !!! UNFINISHED
    pBIO digest_bio(BIO_new(BIO_s_mem()), BIO_free);
    BIO_write(digest_bio.get(), &digest.digest[0], digest.digest.size());

    // TEST Trusted certificate
    STACK_OF(X509)* signers = PKCS7_get0_signers(signature.get(), nullptr, 0);
    X509_STORE* cert_store = X509_STORE_new();
    X509_STORE_add_cert(cert_store, sk_X509_value(signers, 0));
    
    pBIO out(BIO_new(BIO_s_mem()), BIO_free);
    int verification = PKCS7_verify(signature.get(), signers, cert_store, nullptr, out.get(), PKCS7_BINARY);
    std::cout << "Verification result: " << verification << std::endl;
    std::cout << "OpenSSL error: " << ERR_reason_error_string(ERR_get_error()) << std::endl;
}

/**
 *  @brief  This plugin verifies the authenticode signature of a PE file.
 *
 *  This is the *nix reimplementation of the AuthenticodePlugin which is only
 *  availale on Windows (where digital signatures can be checked easily through
 *  the native API).
 *  This version relies on OpenSSL to perform similar operations. One key 
 *  difference is that the trusted certificate base is not available from
 *  an *nix host and therefore the plugin is unable to determine if the
 *  issuer is trusted. 
 */
class OpenSSLAuthenticodePlugin : public IPlugin
{
    int get_api_version() const override { return 1; }
    
    // ----------------------------------------------------------------------------

    pString get_id() const override {
        return boost::make_shared<std::string>("authenticode");
    }
    
    // ----------------------------------------------------------------------------

    pString get_description() const override {
        return boost::make_shared<std::string>("Checks if the digital signature of the PE is valid.");
    }
    
    // ----------------------------------------------------------------------------

    pResult analyze(const mana::PE& pe) override
    {
        pResult res = create_result();
        
        auto certs = pe.get_certificates();
        if (certs == nullptr || certs->size() == 0) {
            return res; // No authenticode signature.
        }
        
        for (auto it = certs->begin() ; it != certs->end() ; ++it)
        {
            // Disregard non-PKCS7 certificates. According to the spec, they are not
            // supported by Windows.
            if ((*it)->CertificateType != WIN_CERT_TYPE_PKCS_SIGNED_DATA) {
                continue;
            }
            
            // Copy the certificate bytes into an OpenSSL BIO.
            pBIO bio(BIO_new_mem_buf(&(*it)->Certificate[0], (*it)->Certificate.size()), BIO_free);
            if (bio == nullptr) 
            {
                PRINT_WARNING << "[plugin_authenticode] Could not initialize a BIO." << std::endl;
                continue;
            }
            
            // Have OpenSSL parse the certificate and check that it isn't malformed.
            pPKCS7 p(d2i_PKCS7_bio(bio.get(), NULL), PKCS7_free);
            if (!check_pkcs_sanity(p)) {
                continue;
            }

            AuthenticodeDigest digest;
            if (!parse_spc_asn1(p->d.sign->contents->d.other->value.asn1_string, digest))
            {
                PRINT_WARNING << "[plugin_authenticode] Could not read the digest information." << std::endl;
                continue;
            }

            // The PKCS7 certificate has been parsed successfully. Start the analysis.
            add_certificate_information(p, res);
            verify_signature(pe, p, digest, res);
            res->set_summary("The PE is digitally signed.");
        }
        
        return res;
    }
};

// ----------------------------------------------------------------------------

extern "C"
{
    PLUGIN_API IPlugin* create() { return new OpenSSLAuthenticodePlugin(); }
    PLUGIN_API void destroy(IPlugin* p) { if (p) delete p; }
};

} //!namespace plugin