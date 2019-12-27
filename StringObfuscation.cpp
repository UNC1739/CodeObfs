//===- StringObfuscation.cpp - Obfuscates the usage of static string constants  ---------------===//

#include <string>
#include <vector>

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/Function.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/IR/GlobalValue.h"

using namespace llvm;

#define DEBUG_TYPE "StringObfs"

namespace {

  struct StringObfuscation : public ModulePass {
    static char ID;
    StringObfuscation() : ModulePass(ID) {}
    std::vector<GlobalVariable*> staticStrings;

    bool runOnModule(Module &M) override {

      //
      // Enumerate all static string constants within the module that we can encrypt
      //

      for(Module::global_iterator gi = M.global_begin(), ge = M.global_end(); gi != ge; ++gi) {
	GlobalVariable *global = &(*gi);
	std::string section(global->getSection());

	//
	// Determine if global variable is a string constant with an initializer and that the 
	// string is not an objective-c method name or llvm related metadata. Then add them to a
	// list of strings that can be replaced.
	//

	if(global->getName().str().substr(0, 4) == ".str" &&
	    global->isConstant() &&
	    global->hasInitializer() &&
	    isa<ConstantDataSequential>(global->getInitializer()) &&
	    section != "llvm.metadata" &&
	    section.find("__objc_methname") == std::string::npos) {

	  ConstantDataArray *str = dyn_cast<ConstantDataArray>(global->getInitializer());

	  if(str == nullptr) {
	    continue;
	  }

	  staticStrings.push_back(global);
	}
      }

      //
      // We iterate over every instruction in every function within the module. From this we
      // analyze the operands for every instruction to identify operands that reference global
      // variables that are referenced as static string constants.
      //

      for(Function &F : M) {
	errs() << "String Obfuscation - Processing Function: ";
	errs().write_escaped(F.getName()) << "\n";
	for(BasicBlock &B : F) {
	  for(Instruction &I : B) {
	    for(Use &arg : I.operands()) {
	      if(isa<GEPOperator>(arg)) {
		GEPOperator *gepo = dyn_cast<GEPOperator>(arg);

		if(isa<GlobalVariable>(gepo->getPointerOperand())) {
		  GlobalVariable *gv = dyn_cast<GlobalVariable>(gepo->getPointerOperand());
		  errs() << "GEPOperator == GlobalVariable" << "\n";
		  errs() << "GV:" << *gv << "\n";

		  // TODO: Find a better way to identify if an object exists within a vector. Alternatively
		  //       we should switch to a set or other object that is better for this.
		  auto entry = std::find(staticStrings.begin(), staticStrings.end(), gv);
		  if(entry != staticStrings.end()) {
		    errs() << "Found Entry in Static Strings" << "\n";

		    //
		    // Do the work necessary to insert LLVM IR code into the beginning of 
		    // the basic block
		    //

		    LLVMContext &Context = B.getContext();
		    IRBuilder<NoFolder> builder(&B);
		    builder.SetInsertPoint(&I);

		    //
		    // Get the contents of the string referenced by the local variable
		    //

		    ConstantDataArray *strObject = dyn_cast<ConstantDataArray>(gv->getInitializer());
		    StringRef strRef = strObject->getAsCString();
		    const char *constStr = strRef.data();
		    size_t constStrSize = strRef.size();

		    //
		    // Allocate a temporary stack buffer to decrypt the encrypted variable
		    // onto the stack
		    //

		    AllocaInst *decryptStrBuf = builder.CreateAlloca(
			builder.getInt8Ty(),
			builder.getInt32(constStrSize + 1) // plus one because the size doesn't include a null terminator
			);

		    //
		    // Create sequence of instructions to perform decryption operation and
		    // write the decrypted string to the stack variable
		    //

		    for(size_t i = 0; i < constStrSize; i++) {

		      //
		      // Generate a byte to XOR with the plaintext string at location "i" and then include 
		      // the decryption operation with the key embedded within the decryption code
		      //

		      int8_t key = rand() % 254 + 1;
		      Value *plaintext = builder.CreateXor(
			  ConstantInt::get(Type::getInt8Ty(Context), constStr[i] ^ key),
			  ConstantInt::get(Type::getInt8Ty(Context), key)
			  );


		      //
		      // Get a pointer to the offset in the buffer corresponding to the correct
		      // position in the string
		      //

		      std::vector<Value *> values;
		      values.push_back(
			  Constant::getIntegerValue(Type::getInt8Ty(Context), APInt(32, i))
			  );

		      Value *gep = builder.CreateGEP(
			  decryptStrBuf,
			  values
			  );

		      //
		      // Construct a store operation to store the decrypted byte of
		      // the string onto the stack
		      //

		      Value *store = builder.CreateStore(
			  plaintext,
			  gep,
			  true);

		    }

		    //
		    // Generate a "GEP" instruction to get a pointer to the last byte of
		    // the string plus one to write the null terminator
		    //

		    std::vector<Value *> values;
		    values.push_back(
			Constant::getIntegerValue(Type::getInt8Ty(Context), APInt(32, constStrSize))
			);

		    Value *gep = builder.CreateGEP(
			decryptStrBuf,
			values
			);

		    //
		    // Create the store instruction to write the null terminator value
		    //

		    Value *store = builder.CreateStore(
			ConstantInt::get(Type::getInt8Ty(Context), 0),
			gep,
			true);

		    //
		    // Replace the reference to the global variable in the operator to
		    // reference the string on the stack 
		    //

		    I.setOperand(arg.getOperandNo(), decryptStrBuf);
		  }
		}
	      }
	    }
	  }
	}
      }

      //
      // Now that the global string constants have been moved into the IR and encrypted
      // we can delete the global variables from the module so that the string constants
      // are no longer present in the binary 
      //

      while(!staticStrings.empty()) {
	GlobalVariable *gv = staticStrings.back();
	staticStrings.pop_back();

	gv->eraseFromParent();
      }

      return true;
    }
  };
}

char StringObfuscation::ID = 0;
static RegisterPass<StringObfuscation> Y("stringobfs", "Obfuscate usage of strings by encrypting and/or duplicating them");
