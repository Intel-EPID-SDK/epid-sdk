/*
@ @licstart  The following is the entire license notice for the
JavaScript code in this file.

Copyright (C) 1997-2017 by Dimitri van Heesch

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

@licend  The above is the entire license notice
for the JavaScript code in this file
*/
var NAVTREE =
[
  [ "Intel® Enhanced Privacy ID SDK", "index.html", [
    [ " ", "user", null ],
    [ "Introducing the Intel® EPID SDK", "index.html", [
      [ "Getting Started", "index.html#mainpage_roadmap", null ]
    ] ],
    [ "Legal Information", "_legal_information.html", null ],
    [ "What's New", "_change_log.html", null ],
    [ "Introduction to the Intel® EPID Scheme", "_epid_overview.html", [
      [ "Roles", "_epid_overview.html#EpidOverview_Roles", [
        [ "Issuers", "_epid_overview.html#EpidOverview_Issuers", null ],
        [ "Members", "_epid_overview.html#EpidOverview_Members", null ],
        [ "Verifiers", "_epid_overview.html#EpidOverview_Verifiers", null ]
      ] ],
      [ "Member and Verifier Interaction", "_epid_overview.html#EpidOverview_Entity_interaction", null ],
      [ "Groups", "_epid_overview.html#EpidOverview_Groups", null ],
      [ "Keys", "_epid_overview.html#EpidOverview_Keys", [
        [ "Group Public Key", "_epid_overview.html#EpidOverview_Group_public_key", null ],
        [ "Issuing Private Key", "_epid_overview.html#EpidOverview_Issuing_private_key", null ],
        [ "Member Private Key", "_epid_overview.html#EpidOverview_Member_private_key", null ]
      ] ]
    ] ],
    [ "What's Included in the SDK", "_sdk_overview.html", [
      [ "SDK Components", "_sdk_overview.html#SdkOverview_Components", [
        [ "SDK Core", "_sdk_overview.html#SdkOverview_Core", null ],
        [ "Samples", "_sdk_overview.html#SdkOverview_Samples", null ],
        [ "Tools", "_sdk_overview.html#SdkOverview_Tools", null ],
        [ "Other Components", "_sdk_overview.html#SdkOverview_BuildingAndValidation", null ]
      ] ],
      [ "Intel® EPID 1.1 Compatibility", "_sdk_overview.html#SdkOverview_Compatibility", null ],
      [ "Member Implementations", "_sdk_overview.html#SdkOverview_TPM", null ],
      [ "Folder Layout", "_sdk_overview.html#SdkOverview_Files", [
        [ "Source Layout", "_sdk_overview.html#SdkOverview_Files_SourceLayout", null ],
        [ "Install Layout", "_sdk_overview.html#SdkOverview_Files_InstallLayout", null ]
      ] ]
    ] ],
    [ "Building from Source", "_building_sdk.html", [
      [ "Prerequisites", "_building_sdk.html#BuildingSdk_Prerequisites", null ],
      [ "Building SDK with SCons", "_building_sdk.html#BuildingSdk_Building_SCons", null ],
      [ "Alternate Makefile Based Build Approach", "_building_sdk.html#BuildingSdk_Building_Makefile", null ],
      [ "Improving Performance with Commercial IPP", "_building_sdk.html#BuildingSdk_CommercialIpp", null ],
      [ "Optimizing for Code Size", "_building_sdk.html#BuildingSdk_Tiny", [
        [ "Limitations", "_building_sdk.html#implementation_TinyLimitations", null ]
      ] ],
      [ "Example Programs", "_building_sdk.html#BuildingSdk_Examples", null ],
      [ "Building with Other Build Systems", "_building_sdk.html#BuildingSdk_PortingBuildSystem", null ]
    ] ],
    [ "Signing and Verification Tutorial", "_sign_verify_tutorial.html", [
      [ "Creating an Intel® EPID Signature of a Given Message", "_sign_verify_tutorial.html#tutorial_signmmsgOverview", [
        [ "What Do You Need to Create a Signature?", "_sign_verify_tutorial.html#tutorial_signmsgList", null ],
        [ "Signing Example", "_sign_verify_tutorial.html#tutorial_signmsgExample", null ]
      ] ],
      [ "Verifying an Intel® EPID Signature", "_sign_verify_tutorial.html#tutorial_verifysigOverview", [
        [ "What Do You Need to Verify a Signature?", "_sign_verify_tutorial.html#tutorial_verifyList", null ],
        [ "Verification Example", "_sign_verify_tutorial.html#tutorial_verifyExample", null ]
      ] ],
      [ "Parameter Matching Requirements", "_sign_verify_tutorial.html#SignVerifyTutorial_requirements", [
        [ "Message", "_sign_verify_tutorial.html#SignVerifyTutorial_message", null ],
        [ "Hash Algorithm", "_sign_verify_tutorial.html#SignVerifyTutorial_hashalg", null ],
        [ "Signature Revocation List", "_sign_verify_tutorial.html#SignVerifyTutorial_SigRL", null ],
        [ "Basenames", "_sign_verify_tutorial.html#SignVerifyTutorial_basenames", null ]
      ] ],
      [ "Revocation", "_sign_verify_tutorial.html#SignVerifyTutorial_Revocation_Group", [
        [ "Detecting Revoked Group from Group Revocation List", "_sign_verify_tutorial.html#SignVerifyTutorial_GroupRevocation", null ],
        [ "Detecting Revoked Member from Private Key Based Revocation List", "_sign_verify_tutorial.html#SignVerifyTutorial_KeyRevocation", null ],
        [ "Detecting Revoked Member from Signature Based Revocation List", "_sign_verify_tutorial.html#SignVerifyTutorial_SigRevocation", null ]
      ] ]
    ] ],
    [ "Preparing a Device", "_provisioning.html", [
      [ "Bulk Provisioning", "_provisioning.html#Provisioning_BulkProvisioning", null ],
      [ "Dynamic Provisioning", "_provisioning.html#Provisioning_JoinProvisioning", null ],
      [ "Issuer Material", "_provisioning.html#SampleIssuerMaterial", [
        [ "Issuer Material for Verifiers", "_provisioning.html#Provisioning_ValidatingVerifiers", null ],
        [ "Issuer Material for Members", "_provisioning.html#Provisioning_ValidatingMembers", null ]
      ] ]
    ] ],
    [ "Test Data", "_issuer_material.html", [
      [ "Sample Groups", "_issuer_material.html#IssuerMaterial_Groups", null ],
      [ "Group Revocation Lists", "_issuer_material.html#IssuerMaterial_GroupRls", null ],
      [ "Compressed Sample Groups", "_issuer_material.html#CompressedSamples", null ],
      [ "Compressed Group Revocation Lists", "_issuer_material.html#IssuerMaterial_CmpGroupRls", null ]
    ] ],
    [ "Managing Groups with iKGF", "_usingi_k_g_f.html", [
      [ "Contacting iKGF", "_usingi_k_g_f.html#ContactingiKGF", null ],
      [ "Tools for Creating Revocation Requests", "_usingi_k_g_f.html#RevocationTools", [
        [ "Requesting Group Revocation", "_usingi_k_g_f.html#RevocationTools_revokegrp", null ],
        [ "Requesting Private Key Revocation", "_usingi_k_g_f.html#RevocationTools_revokekey", null ],
        [ "Requesting Signature Revocation", "_usingi_k_g_f.html#RevocationTools_revokesig", null ]
      ] ],
      [ "Tools for Extracting Keys from iKGF Files", "_usingi_k_g_f.html#ExtractionTools", [
        [ "Extracting Group Public Keys", "_usingi_k_g_f.html#ExtractionTools_extractgrps", null ],
        [ "Extracting Member Private Keys", "_usingi_k_g_f.html#ExtractionTools_extractkeys", null ]
      ] ]
    ] ],
    [ "In-Depth Explanation of Revocation", "_revocation.html", [
      [ "Revocation Hierarchy", "_revocation.html#revocation_hierarchy", null ],
      [ "Revocation List Versions", "_revocation.html#revocation_versions", null ],
      [ "Group Based Revocation", "_revocation.html#group_revocation", [
        [ "Reasons the Issuer Might Revoke a Group", "_revocation.html#group_revocation_reasons", null ]
      ] ],
      [ "Private Key Based Revocation", "_revocation.html#private_key_revocation", [
        [ "Reasons the Issuer Might Revoke a Member Private Key", "_revocation.html#private_key_revocation_reasons", null ]
      ] ],
      [ "Signature Based Revocation", "_revocation.html#signature_revocation", [
        [ "Signing with Non-Revoked Proofs", "_revocation.html#revoked_proofs", null ],
        [ "Reasons the Issuer Might Revoke an Intel® EPID Signature", "_revocation.html#signature_revocation_reasons", null ]
      ] ],
      [ "Verifier Blacklist Revocation", "_revocation.html#verifier_blacklist", [
        [ "Reasons the Verifier Might Revoke an Intel® EPID Signature", "_revocation.html#verifier_blacklist_reasons", null ]
      ] ]
    ] ],
    [ "In-Depth Explanation of Basenames", "_basenames.html", [
      [ "Random Base Signatures", "_basenames.html#random_base", null ],
      [ "Name Based Signatures", "_basenames.html#name_based", null ]
    ] ],
    [ "Implementation Notes", "_implementation_notes.html", [
      [ "Member Implementations", "_implementation_notes.html#implementationNotes_Members", null ],
      [ "Random Number Generation", "_implementation_notes.html#ImplementationNotes_Prng", null ],
      [ "Protecting Secrets", "_implementation_notes.html#ImplementationNotes_ProtectingSecrets", null ],
      [ "Replacing Math Primitives", "_implementation_notes.html#ImplementationNotes_MathPrimitives", null ],
      [ "Octstring/Buffer Types", "_implementation_notes.html#ImplementationNotes_SerializedTypes", null ],
      [ "Flexible Arrays", "_implementation_notes.html#ImplementationNotes_FlexibleArrays", null ]
    ] ],
    [ "Considerations for TPM", "_tpm_considerations.html", [
      [ "Compatibility", "_tpm_considerations.html#TPM_compatibility", null ],
      [ "Considerations for TPM Manufacturers", "_tpm_considerations.html#TpmConsiderations_Manufacturers", [
        [ "Provisioning TPM with Intel® EPID Key Material", "_tpm_considerations.html#TPM_provisioning", null ],
        [ "Mapping TPM Commands to Intel® EPID", "_tpm_considerations.html#TpmConsiderations_Mapping", null ]
      ] ],
      [ "Considerations for TPM Applications", "_tpm_considerations.html#TpmConsiderations_Applications", null ],
      [ "SDK Member Architecture", "_tpm_considerations.html#TpmConsiderations_Architecture", null ],
      [ "Building the SDK to Take Advantage of TPM", "_tpm_considerations.html#TpmConsiderations_Building", [
        [ "Prerequisites to Build the SDK in TPM Mode", "_tpm_considerations.html#TpmConsiderations_Prereqs", null ],
        [ "Building the SDK in TPM Mode", "_tpm_considerations.html#TpmConsiderations_BuildingTpmMode", null ],
        [ "Intel® EPID Signing and Verification with a TPM", "_tpm_considerations.html#TpmConsiderations_Signing", null ]
      ] ]
    ] ],
    [ "Glossary", "_glossary.html", [
      [ "CA public key", "_glossary.html#Issuing_CA", null ],
      [ "DAA", "_glossary.html#Glossary_Daa", null ],
      [ "Elliptic curve", "_glossary.html#Glossary_EllipticCurve", null ],
      [ "Elliptic curve point", "_glossary.html#Glossary_EllipticCurvePoint", null ],
      [ "Group", "_glossary.html#Glossary_Group", null ],
      [ "Group certificate", "_glossary.html#Glossary_Group_certificate", null ],
      [ "Group public key", "_glossary.html#Glossary_GroupPublicKey", null ],
      [ "Intel® EPID", "_glossary.html#Glossary_Epid", null ],
      [ "Intel® EPID signature", "_glossary.html#Glossary_EpidSignature", null ],
      [ "Issuer", "_glossary.html#Glossary_Issuer", null ],
      [ "Issuing private key", "_glossary.html#Glossary_IssuingPrivateKey", null ],
      [ "Member", "_glossary.html#Glossary_Member", null ],
      [ "Name-based signature", "_glossary.html#Glossary_NameBasedSignature", null ],
      [ "Member private key", "_glossary.html#Glossary_MemberPrivateKey", null ],
      [ "Non-revoked proof", "_glossary.html#Glossary_NonRevokedProof", null ],
      [ "Pairing", "_glossary.html#Glossary_Pairing", null ],
      [ "Revocation, revocation lists", "_glossary.html#Glossary_Revocation", null ],
      [ "Verifier", "_glossary.html#Glossary_Verifier", null ]
    ] ],
    [ "Guide to Installing Build Tools", "_build_tools_installation.html", [
      [ "Installing Python", "_build_tools_installation.html#build_tools_windows_python", null ],
      [ "Installing SCons", "_build_tools_installation.html#build_tools_windows_scons", null ],
      [ "Installing Parts", "_build_tools_installation.html#build_tools_windows_parts", null ]
    ] ],
    [ "Tested Libraries and Compilers", "_how_validated.html", [
      [ "Tested Libraries and Compilers", "_how_validated.html#validated_supported_compilers", null ]
    ] ],
    [ "Walkthroughs of Examples Showing API Usage", "_examples.html", "_examples" ],
    [ "Deprecated List", "deprecated.html", null ],
    [ "API Reference", "modules.html", "modules" ]
  ] ]
];

var NAVTREEINDEX =
[
"_basenames.html",
"group___epid_types.html#gace6876a045f2c2694444b35ccb0844e2",
"struct_fp_elem_str.html"
];

var SYNCONMSG = 'click to disable panel synchronisation';
var SYNCOFFMSG = 'click to enable panel synchronisation';