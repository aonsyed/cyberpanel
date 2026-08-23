//go:build linux

package apps

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const DefaultApplicationCatalogRoot = "/usr/share/cyberpanel/application-catalog"

type LinuxRecipeCatalogAuthority struct{Root string}
func NewLinuxRecipeCatalogAuthority(root string)(*LinuxRecipeCatalogAuthority,error){if root==""{root=DefaultApplicationCatalogRoot};if !filepath.IsAbs(root)||filepath.Clean(root)!=root{return nil,ErrInvalid};return &LinuxRecipeCatalogAuthority{root},nil}
func(authority *LinuxRecipeCatalogAuthority)FetchRecipe(_ context.Context,reference RecipeReference)(SignedRecipeDocument,error){if authority==nil||!validID(string(reference.ID)){return SignedRecipeDocument{},ErrInvalid};path:=filepath.Join(authority.Root,"recipes",string(reference.ID)+".json");if !strings.HasPrefix(path,filepath.Join(authority.Root,"recipes")+string(os.PathSeparator)){return SignedRecipeDocument{},ErrPolicyDenied};info,err:=os.Lstat(path);if err!=nil{return SignedRecipeDocument{},err};if !info.Mode().IsRegular()||info.Mode()&os.ModeSymlink!=0||info.Size()<=0||info.Size()>4<<20{return SignedRecipeDocument{},ErrRecipeUntrusted};encoded,err:=os.ReadFile(path);if err!=nil{return SignedRecipeDocument{},err};var document SignedRecipeDocument;decoder:=json.NewDecoder(strings.NewReader(string(encoded)));decoder.DisallowUnknownFields();if decoder.Decode(&document)!=nil||decoder.Decode(&struct{}{})!=io.EOF||len(document.CanonicalPayload)==0||len(document.Signature)!=ed25519.SignatureSize{return SignedRecipeDocument{},ErrRecipeUntrusted};return document,nil}
func(authority *LinuxRecipeCatalogAuthority)ReferenceByID(ctx context.Context,id RecipeID)(RecipeReference,error){if authority==nil||!validID(string(id)){return RecipeReference{},ErrInvalid};document,err:=authority.FetchRecipe(ctx,RecipeReference{ID:id});if err!=nil{return RecipeReference{},err};if document.Reference.ID!=id||document.Reference.Validate(time.Now().UTC())!=nil{return RecipeReference{},ErrRecipeUntrusted};if err=authority.VerifyRecipe(ctx,document.Reference.SigningKeyID,document.Reference.CatalogEpoch,document.CanonicalPayload,document.Signature);err!=nil{return RecipeReference{},err};return document.Reference,nil}
func(authority *LinuxRecipeCatalogAuthority)VerifyRecipe(_ context.Context,keyID string,epoch uint64,payload,signature []byte)error{if authority==nil||!validID(keyID)||epoch==0||len(payload)==0||len(signature)!=ed25519.SignatureSize{return ErrRecipeUntrusted};path:=filepath.Join(authority.Root,"keys",keyID+".pub");if !strings.HasPrefix(path,filepath.Join(authority.Root,"keys")+string(os.PathSeparator)){return ErrRecipeUntrusted};info,err:=os.Lstat(path);if err!=nil||!info.Mode().IsRegular()||info.Mode()&os.ModeSymlink!=0||info.Size()<=0||info.Size()>4096{return ErrRecipeUntrusted};encoded,err:=os.ReadFile(path);if err!=nil{return ErrRecipeUntrusted};block,_:=pem.Decode(encoded);var publicKey ed25519.PublicKey;if block!=nil&&block.Type=="PUBLIC KEY"{parsed,parseErr:=x509.ParsePKIXPublicKey(block.Bytes);if parseErr!=nil{return ErrRecipeUntrusted};typed,ok:=parsed.(ed25519.PublicKey);if !ok{return ErrRecipeUntrusted};publicKey=typed}else{decoded,decodeErr:=hex.DecodeString(strings.TrimSpace(string(encoded)));if decodeErr!=nil||len(decoded)!=ed25519.PublicKeySize{return ErrRecipeUntrusted};publicKey=ed25519.PublicKey(decoded)};if len(publicKey)!=ed25519.PublicKeySize||!ed25519.Verify(publicKey,payload,signature){return ErrRecipeUntrusted};return nil}
func(authority *LinuxRecipeCatalogAuthority)VerifyAutologinBridge(_ context.Context,keyID,digest,signature string)error{if !validDigest(digest)||signature==""{return ErrRecipeUntrusted};decoded,err:=hex.DecodeString(signature);if err!=nil{return ErrRecipeUntrusted};return authority.VerifyRecipe(context.Background(),keyID,1,[]byte(digest),decoded)}

func NewLinuxPinnedApplicationCatalog(root string)(*PinnedCatalog,*LinuxRecipeCatalogAuthority,error){authority,err:=NewLinuxRecipeCatalogAuthority(root);if err!=nil{return nil,nil,err};catalog:=&PinnedCatalog{Source:authority,Verifier:authority,MinimumEpoch:1,MaximumPayload:4<<20};return catalog,authority,nil}

var _ RecipeSource=(*LinuxRecipeCatalogAuthority)(nil)
var _ RecipeVerifier=(*LinuxRecipeCatalogAuthority)(nil)
var _ AutologinBridgeVerifier=(*LinuxRecipeCatalogAuthority)(nil)
