var NAVTREE =
[
  [ "Intel® Enhanced Privacy ID SDK", "index.html", [
    [ " ", "user", null ],
    [ "Introducing the Intel® EPID SDK", "index.html", [
      [ "Getting Started", "index.html#mainpage_roadmap", null ]
    ] ],
    [ "Legal Information", "LegalInformation.html", null ],
    [ "What's New", "ChangeLog.html", null ],
    [ "Introduction to the Intel® EPID Scheme", "EpidOverview.html", [
      [ "Roles", "EpidOverview.html#EpidOverview_Roles", [
        [ "Issuers", "EpidOverview.html#EpidOverview_Issuers", null ],
        [ "Members", "EpidOverview.html#EpidOverview_Members", null ],
        [ "Verifiers", "EpidOverview.html#EpidOverview_Verifiers", null ]
      ] ],
      [ "Member and Verifier Interaction", "EpidOverview.html#EpidOverview_Entity_interaction", null ],
      [ "Groups", "EpidOverview.html#EpidOverview_Groups", null ],
      [ "Keys", "EpidOverview.html#EpidOverview_Keys", [
        [ "Group Public Key", "EpidOverview.html#EpidOverview_Group_public_key", null ],
        [ "Issuing Private Key", "EpidOverview.html#EpidOverview_Issuing_private_key", null ],
        [ "Member Private Key", "EpidOverview.html#EpidOverview_Member_private_key", null ]
      ] ]
    ] ],
    [ "What's Included in the SDK", "SdkOverview.html", [
      [ "SDK Components", "SdkOverview.html#SdkOverview_Components", null ],
      [ "SDK Core", "SdkOverview.html#SdkOverview_Core", null ],
      [ "Samples", "SdkOverview.html#SdkOverview_Samples", null ],
      [ "Tools", "SdkOverview.html#SdkOverview_Tools", null ],
      [ "Building and Validation", "SdkOverview.html#SdkOverview_BuildingAndValidation", null ],
      [ "Intel® EPID 1.1 Compatibility", "SdkOverview.html#SdkOverview_Compatibility", null ],
      [ "Folder Layout", "SdkOverview.html#SdkOverview_Files", [
        [ "Source Layout", "SdkOverview.html#SdkOverview_Files_SourceLayout", null ],
        [ "Install Layout", "SdkOverview.html#SdkOverview_Files_InstallLayout", null ]
      ] ]
    ] ],
    [ "Building from Source", "BuildingSdk.html", [
      [ "Prerequisites", "BuildingSdk.html#BuildingSdk_Prerequisites", null ],
      [ "Building SDK with SCons", "BuildingSdk.html#BuildingSdk_Building_SCons", null ],
      [ "Alternate Makefile/Autoconf Based Build Approach", "BuildingSdk.html#BuildingSdk_Building_Makefile", null ],
      [ "Improving Performance with Commercial IPP", "BuildingSdk.html#BuildingSdk_CommercialIpp", null ],
      [ "Optimizing Code Size over Performance", "BuildingSdk.html#BuildingSdk_SizeOptimizedBuild", null ],
      [ "Example Programs", "BuildingSdk.html#BuildingSdk_Examples", null ],
      [ "Building with Other Build Systems", "BuildingSdk.html#BuildingSdk_PortingBuildSystem", null ]
    ] ],
    [ "Signing and Verification Tutorial", "SignVerifyTutorial.html", [
      [ "Creating an Intel® EPID Signature of a Given Message", "SignVerifyTutorial.html#tutorial_signmmsgOverview", [
        [ "What Do You Need to Create a Signature?", "SignVerifyTutorial.html#tutorial_signmsgList", null ],
        [ "Signing Example", "SignVerifyTutorial.html#tutorial_signmsgExample", null ]
      ] ],
      [ "Verifying an Intel® EPID Signature", "SignVerifyTutorial.html#tutorial_verifysigOverview", [
        [ "What Do You Need to Verify a Signature?", "SignVerifyTutorial.html#tutorial_verifyList", null ],
        [ "Verification Example", "SignVerifyTutorial.html#tutorial_verifyExample", null ]
      ] ],
      [ "Parameter Matching Requirements", "SignVerifyTutorial.html#SignVerifyTutorial_requirements", [
        [ "Message", "SignVerifyTutorial.html#SignVerifyTutorial_message", null ],
        [ "Hash Algorithm", "SignVerifyTutorial.html#SignVerifyTutorial_hashalg", null ],
        [ "Signature Revocation List", "SignVerifyTutorial.html#SignVerifyTutorial_SigRL", null ],
        [ "Basenames", "SignVerifyTutorial.html#SignVerifyTutorial_basenames", null ]
      ] ],
      [ "Revocation", "SignVerifyTutorial.html#SignVerifyTutorial_Revocation_Group", [
        [ "Detecting Revoked Group from Group Revocation List", "SignVerifyTutorial.html#SignVerifyTutorial_GroupRevocation", null ],
        [ "Detecting Revoked Member from Private Key Based Revocation List", "SignVerifyTutorial.html#SignVerifyTutorial_KeyRevocation", null ],
        [ "Detecting Revoked Member from Signature Based Revocation List", "SignVerifyTutorial.html#SignVerifyTutorial_SigRevocation", null ]
      ] ]
    ] ],
    [ "Preparing a Device", "Provisioning.html", [
      [ "Bulk Provisioning", "Provisioning.html#Provisioning_BulkProvisioning", null ],
      [ "Dynamic Provisioning", "Provisioning.html#Provisioning_JoinProvisioning", null ],
      [ "Issuer Material", "Provisioning.html#SampleIssuerMaterial", [
        [ "Issuer Material for Verifiers", "Provisioning.html#Provisioning_ValidatingVerifiers", null ],
        [ "Issuer Material for Members", "Provisioning.html#Provisioning_ValidatingMembers", null ]
      ] ]
    ] ],
    [ "Test Data", "IssuerMaterial.html", [
      [ "Sample Groups", "IssuerMaterial.html#IssuerMaterial_Groups", null ],
      [ "Group Revocation Lists", "IssuerMaterial.html#IssuerMaterial_GroupRls", null ],
      [ "Compressed Sample Groups", "IssuerMaterial.html#CompressedSamples", null ],
      [ "Compressed Group Revocation Lists", "IssuerMaterial.html#IssuerMaterial_CmpGroupRls", null ]
    ] ],
    [ "Managing Groups with iKGF", "UsingiKGF.html", [
      [ "Contacting iKGF", "UsingiKGF.html#ContactingiKGF", null ],
      [ "Tools for Creating Revocation Requests", "UsingiKGF.html#RevocationTools", [
        [ "Requesting Group Revocation", "UsingiKGF.html#RevocationTools_revokegrp", null ],
        [ "Requesting Private Key Revocation", "UsingiKGF.html#RevocationTools_revokekey", null ],
        [ "Requesting Signature Revocation", "UsingiKGF.html#RevocationTools_revokesig", null ]
      ] ],
      [ "Tools for Extracting Keys from iKGF Files", "UsingiKGF.html#ExtractionTools", [
        [ "Extracting Group Public Keys", "UsingiKGF.html#ExtractionTools_extractgrps", null ],
        [ "Extracting Member Private Keys", "UsingiKGF.html#ExtractionTools_extractkeys", null ]
      ] ]
    ] ],
    [ "In-Depth Explanation of Revocation", "Revocation.html", [
      [ "Revocation Hierarchy", "Revocation.html#revocation_hierarchy", null ],
      [ "Revocation List Versions", "Revocation.html#revocation_versions", null ],
      [ "Group Based Revocation", "Revocation.html#group_revocation", [
        [ "Reasons the Issuer Might Revoke a Group", "Revocation.html#group_revocation_reasons", null ]
      ] ],
      [ "Private Key Based Revocation", "Revocation.html#private_key_revocation", [
        [ "Reasons the Issuer Might Revoke a Member Private Key", "Revocation.html#private_key_revocation_reasons", null ]
      ] ],
      [ "Signature Based Revocation", "Revocation.html#signature_revocation", [
        [ "Signing with Non-Revoked Proofs", "Revocation.html#revoked_proofs", null ],
        [ "Reasons the Issuer Might Revoke an Intel® EPID Signature", "Revocation.html#signature_revocation_reasons", null ]
      ] ],
      [ "Verifier Blacklist Revocation", "Revocation.html#verifier_blacklist", [
        [ "Reasons the Verifier Might Revoke an Intel® EPID Signature", "Revocation.html#verifier_blacklist_reasons", null ]
      ] ]
    ] ],
    [ "In-Depth Explanation of Basenames", "Basenames.html", [
      [ "Random Base Signatures", "Basenames.html#random_base", null ],
      [ "Name Based Signatures", "Basenames.html#name_based", null ]
    ] ],
    [ "Implementation Notes", "ImplementationNotes.html", [
      [ "Random Number Generation", "ImplementationNotes.html#ImplementationNotes_Prng", null ],
      [ "Protecting Secrets", "ImplementationNotes.html#ImplementationNotes_ProtectingSecrets", null ],
      [ "Replacing Math Primitives", "ImplementationNotes.html#ImplementationNotes_MathPrimitives", null ],
      [ "Octstring/Buffer Types", "ImplementationNotes.html#ImplementationNotes_SerializedTypes", null ],
      [ "Flexible Arrays", "ImplementationNotes.html#ImplementationNotes_FlexibleArrays", null ]
    ] ],
    [ "Considerations for TPM", "TpmConsiderations.html", [
      [ "Compatibility", "TpmConsiderations.html#TPM_compatibility", null ],
      [ "Considerations for TPM Manufacturers", "TpmConsiderations.html#TpmConsiderations_Manufacturers", [
        [ "Provisioning TPM with Intel® EPID Key Material", "TpmConsiderations.html#TPM_provisioning", null ],
        [ "Mapping TPM Commands to Intel® EPID", "TpmConsiderations.html#TpmConsiderations_Mapping", null ]
      ] ],
      [ "Considerations for TPM Applications", "TpmConsiderations.html#TpmConsiderations_Applications", null ],
      [ "SDK Member Architecture", "TpmConsiderations.html#TpmConsiderations_Architecture", null ],
      [ "Building the SDK to Take Advantage of TPM", "TpmConsiderations.html#TpmConsiderations_Building", [
        [ "Prerequisites to Build the SDK in TPM Mode", "TpmConsiderations.html#TpmConsiderations_Prereqs", null ],
        [ "Building the SDK in TPM Mode", "TpmConsiderations.html#TpmConsiderations_BuildingTpmMode", null ],
        [ "Intel® EPID Signing and Verification", "TpmConsiderations.html#TpmConsiderations_Signing", null ]
      ] ]
    ] ],
    [ "Glossary", "Glossary.html", [
      [ "CA public key", "Glossary.html#Issuing_CA", null ],
      [ "DAA", "Glossary.html#Glossary_Daa", null ],
      [ "Elliptic curve", "Glossary.html#Glossary_EllipticCurve", null ],
      [ "Elliptic curve point", "Glossary.html#Glossary_EllipticCurvePoint", null ],
      [ "Group", "Glossary.html#Glossary_Group", null ],
      [ "Group certificate", "Glossary.html#Glossary_Group_certificate", null ],
      [ "Group public key", "Glossary.html#Glossary_GroupPublicKey", null ],
      [ "Intel® EPID", "Glossary.html#Glossary_Epid", null ],
      [ "Intel® EPID signature", "Glossary.html#Glossary_EpidSignature", null ],
      [ "Issuer", "Glossary.html#Glossary_Issuer", null ],
      [ "Issuing private key", "Glossary.html#Glossary_IssuingPrivateKey", null ],
      [ "Member", "Glossary.html#Glossary_Member", null ],
      [ "Name-based signature", "Glossary.html#Glossary_NameBasedSignature", null ],
      [ "Member private key", "Glossary.html#Glossary_MemberPrivateKey", null ],
      [ "Non-revoked proof", "Glossary.html#Glossary_NonRevokedProof", null ],
      [ "Pairing", "Glossary.html#Glossary_Pairing", null ],
      [ "Revocation, revocation lists", "Glossary.html#Glossary_Revocation", null ],
      [ "Verifier", "Glossary.html#Glossary_Verifier", null ]
    ] ],
    [ "Guide to Installing Build Tools", "BuildToolsInstallation.html", [
      [ "Installing Python", "BuildToolsInstallation.html#build_tools_windows_python", null ],
      [ "Installing SCons", "BuildToolsInstallation.html#build_tools_windows_scons", null ],
      [ "Installing Parts", "BuildToolsInstallation.html#build_tools_windows_parts", null ]
    ] ],
    [ "Tested Libraries and Compilers", "HowValidated.html", [
      [ "Tested Libraries and Compilers", "HowValidated.html#validated_supported_compilers", null ]
    ] ],
    [ "Walkthroughs of Examples Showing API Usage", "Examples.html", "Examples" ],
    [ "API Reference", "modules.html", "modules" ]
  ] ]
];

var NAVTREEINDEX =
[
"Basenames.html",
"group___epid_types.html#gga5e450438f6f9a5eacd0cf5ce354ec890aefb89989305b5c34120b0f18ee8e2c5d",
"struct_fq3_elem_str.html#af1be0a4d5c9c674d75bec34f95e3c731"
];

var SYNCONMSG = 'click to disable panel synchronisation';
var SYNCOFFMSG = 'click to enable panel synchronisation';