//===- AddJunkCode.cpp - Adds Junk Code Using LLVM  ---------------===//

#include <string>

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

#define DEBUG_TYPE "junk"

namespace {

  struct Junk : public ModulePass {
    static char ID; // Pass identification, replacement for typeid
    Junk() : ModulePass(ID) {}

    bool runOnModule(Module &M) override {

      //
      // Here we create a random global variable that will be referenced
      // by our junk code insertion routine. The purpose of this is to prevent
      // the junk code from being removed when the LLVM dead code removal 
      // optimization is executed. The dead code removal engine will not remove the
      // junk code if it stores the results of bogus computations into a global variable.
      //

      errs() << "Creating Random Global" << "\n";
      IntegerType *I32Ty = Type::getInt32Ty(M.getContext());
      ConstantInt *init = ConstantInt::get(I32Ty, 0);
      GlobalVariable *global = new GlobalVariable(
	    M,
	    init->getType(),
	    false,
	    GlobalVariable::PrivateLinkage,
	    init,
	    "RandomVariable"
	  );

      global->setAlignment(4);

      errs() << "Set Global Variable Info" << "\n";

      //
      // Iterate over each function in the module and insert junk code between all
      // instructions
      //

      for(Function &F : M) {
	for(BasicBlock &blk : F) {
	  errs() << "Processing Function: ";
	  errs().write_escaped(F.getName()) << '\n';

	  LLVMContext &ctx = F.getContext();
	  Value *Lef = ConstantInt::get(Type::getInt32Ty(ctx), rand());

	  for(BasicBlock::iterator i = blk.begin(), e = blk.end(); i != e; ++i) {
	    LLVMContext &Context = blk.getContext();
	    IRBuilder<NoFolder> builder(&blk);

	    builder.SetInsertPoint(&(*i));

	    Value *Rig = ConstantInt::get(Type::getInt32Ty(Context), rand());

	    Value *Result;
	    int choice = rand() % 7;
	    if(choice == 0) {
	      Result = builder.CreateAdd(Lef, Rig);
	    } else if(choice == 1) {
	      Result = builder.CreateSub(Lef, Rig);
	    } else if(choice == 2) {
	      Result = builder.CreateMul(Lef, Rig);
	    } else if(choice == 3) {
	      Result = builder.CreateUDiv(Lef, Rig);
	    } else if(choice == 4) {
	      Result = builder.CreateXor(Lef, Rig);
	    } else if(choice == 5) {
	      Result = builder.CreateAnd(Lef, Rig);
	    } else if(choice == 6) {
	      Result = builder.CreateOr(Lef, Rig);
	    } 

	    Lef = Result;

	    if(isa<ReturnInst>(&(*i))) {
	      Value *store = builder.CreateStore(Result, global, true);
	    }
	  }
	}
      }

      return false;
    }
  };
}

char Junk::ID = 0;
static RegisterPass<Junk> Y("junk", "Pass to Insert Junk Arthimetic Operations Into Compiled Code");
