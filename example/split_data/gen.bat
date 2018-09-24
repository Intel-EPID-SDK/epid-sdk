set GENERATE=%~dp0\..\..\script\generate_testdata.py
set IKGFWRAPPER=%~dp0\..\..\_install\bin\ikgfwrapper.exe
set INC2DAT=%~dp0\..\..\tools\inc2dat.py

%GENERATE% --inplace **/*iprivkey*.inc **/*pubkey*.inc **/*joinreq*.inc **/*credential*.inc **/*mprivkey*.inc
%INC2DAT% **/*pubkey*.inc **/*mprivkey*.inc

%IKGFWRAPPER%  --privkey=issuingca-priv.dat --in=groupa/pubkey.dat  --outtype=GroupPubKey --out=groupa/pubkey.bin
%IKGFWRAPPER%  --upgrade --privkey=issuingca-priv.dat --in=groupa/privrl.bin  --outtype=PrivRl --out=groupa/privrl.bin
%IKGFWRAPPER%  --upgrade --privkey=issuingca-priv.dat --in=groupa/privrl_empty.bin  --outtype=PrivRl --out=groupa/privrl_empty.bin
%IKGFWRAPPER%  --upgrade --privkey=issuingca-priv.dat --in=groupa/sigrl_empty.bin  --outtype=SigRl --out=groupa/sigrl_empty.bin

%IKGFWRAPPER%  --privkey=issuingca-priv.dat --in=groupb/pubkey.dat  --outtype=GroupPubKey --out=groupb/pubkey.bin
%IKGFWRAPPER%  --upgrade --privkey=issuingca-priv.dat --in=groupb/privrl.bin  --outtype=PrivRl --out=groupb/privrl.bin
%IKGFWRAPPER%  --upgrade --privkey=issuingca-priv.dat --in=groupb/privrl_empty.bin  --outtype=PrivRl --out=groupb/privrl_empty.bin
%IKGFWRAPPER%  --upgrade --privkey=issuingca-priv.dat --in=groupb/sigrl_empty.bin  --outtype=SigRl --out=groupb/sigrl_empty.bin

%IKGFWRAPPER%  --upgrade --privkey=issuingca-priv.dat --in=grprl.bin  --outtype=GroupRl --out=grprl.bin
%IKGFWRAPPER%  --upgrade --privkey=issuingca-priv.dat --in=grprl_empty.bin  --outtype=GroupRl --out=grprl_empty.bin
