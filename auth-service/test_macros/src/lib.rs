use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemFn, Stmt, Local, Pat, PatIdent};

/// A procedural macro that automatically adds TestApp cleanup at the end of test functions.
/// 
/// This macro should be applied to test functions that use TestApp. The user must declare
/// the TestApp variable as mutable (`let mut app = TestApp::new(true).await;`).
/// 
/// The macro will automatically add `app.clean_up().await;` at the end of the function.
/// 
/// Usage:
/// ```rust
/// #[with_db_cleanup]
/// #[tokio::test]
/// async fn my_test() {
///     let mut app = TestApp::new(true).await;  // Note: must be mutable
///     // ... test logic ...
///     // clean_up() will be called automatically
/// }
/// ```
#[proc_macro_attribute]
pub fn with_db_cleanup(_args: TokenStream, input: TokenStream) -> TokenStream {
    let mut input_fn = parse_macro_input!(input as ItemFn);
    
    // Check that this is an async function
    if input_fn.sig.asyncness.is_none() {
        panic!("with_db_cleanup can only be applied to async functions");
    }
    
    // Get the original function body statements
    let original_stmts = &input_fn.block.stmts;
    
    // Find if there's a TestApp variable declared
    let mut app_var_name: Option<String> = None;
    
    for stmt in original_stmts {
        if let Stmt::Local(Local { pat, .. }) = stmt {
            if let Pat::Ident(PatIdent { ident, .. }) = pat {
                let var_name = ident.to_string();
                // Look for any variable that might be a TestApp (commonly named 'app')
                if var_name == "app" {
                    app_var_name = Some(var_name);
                    break;
                }
            }
        }
    }
    
    // Create new function body that includes cleanup at the end
    let cleanup_call = match app_var_name {
        Some(var_name) => {
            let var_ident = syn::Ident::new(&var_name, proc_macro2::Span::call_site());
            quote! { #var_ident.clean_up().await; }
        }
        None => {
            // Default to 'app' if we can't find it
            quote! { app.clean_up().await; }
        }
    };
    
    let new_block = syn::parse2(quote! {
        {
            #(#original_stmts)*
            
            // Automatically call cleanup on the TestApp
            #cleanup_call
        }
    }).expect("Failed to parse new function block");
    
    input_fn.block = Box::new(new_block);
    
    TokenStream::from(quote! { #input_fn })
}