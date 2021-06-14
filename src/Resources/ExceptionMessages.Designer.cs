﻿//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//     Runtime Version:4.0.30319.42000
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace Roydl.Crypto.Resources {
    using System;
    
    
    /// <summary>
    ///   A strongly-typed resource class, for looking up localized strings, etc.
    /// </summary>
    // This class was auto-generated by the StronglyTypedResourceBuilder
    // class via a tool like ResGen or Visual Studio.
    // To add or remove a member, edit your .ResX file then rerun ResGen
    // with the /str option, or rebuild your VS project.
    [global::System.CodeDom.Compiler.GeneratedCodeAttribute("System.Resources.Tools.StronglyTypedResourceBuilder", "16.0.0.0")]
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute()]
    [global::System.Runtime.CompilerServices.CompilerGeneratedAttribute()]
    internal class ExceptionMessages {
        
        private static global::System.Resources.ResourceManager resourceMan;
        
        private static global::System.Globalization.CultureInfo resourceCulture;
        
        [global::System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1811:AvoidUncalledPrivateCode")]
        internal ExceptionMessages() {
        }
        
        /// <summary>
        ///   Returns the cached ResourceManager instance used by this class.
        /// </summary>
        [global::System.ComponentModel.EditorBrowsableAttribute(global::System.ComponentModel.EditorBrowsableState.Advanced)]
        internal static global::System.Resources.ResourceManager ResourceManager {
            get {
                if (object.ReferenceEquals(resourceMan, null)) {
                    global::System.Resources.ResourceManager temp = new global::System.Resources.ResourceManager("Roydl.Crypto.Resources.ExceptionMessages", typeof(ExceptionMessages).Assembly);
                    resourceMan = temp;
                }
                return resourceMan;
            }
        }
        
        /// <summary>
        ///   Overrides the current thread's CurrentUICulture property for all
        ///   resource lookups using this strongly typed resource class.
        /// </summary>
        [global::System.ComponentModel.EditorBrowsableAttribute(global::System.ComponentModel.EditorBrowsableState.Advanced)]
        internal static global::System.Globalization.CultureInfo Culture {
            get {
                return resourceCulture;
            }
            set {
                resourceCulture = value;
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to The size in bits is too large for the specified type..
        /// </summary>
        internal static string ArgumentBitsTypeRatioInvalid {
            get {
                return ResourceManager.GetString("ArgumentBitsTypeRatioInvalid", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Parameter is empty..
        /// </summary>
        internal static string ArgumentEmpty {
            get {
                return ResourceManager.GetString("ArgumentEmpty", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Parameter size is too small..
        /// </summary>
        internal static string ArgumentSizeTooSmall {
            get {
                return ResourceManager.GetString("ArgumentSizeTooSmall", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to The destination path is invalid..
        /// </summary>
        internal static string DirectoryNotFoundDestPath {
            get {
                return ResourceManager.GetString("DirectoryNotFoundDestPath", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to File could not be found..
        /// </summary>
        internal static string FileNotFound {
            get {
                return ResourceManager.GetString("FileNotFound", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to The CRC validation failed..
        /// </summary>
        internal static string InvalidDataCrcValidation {
            get {
                return ResourceManager.GetString("InvalidDataCrcValidation", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to The specified type is invalid..
        /// </summary>
        internal static string InvalidOperationUnsupportedType {
            get {
                return ResourceManager.GetString("InvalidOperationUnsupportedType", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to Stream does not support reading..
        /// </summary>
        internal static string NotSupportedStreamRead {
            get {
                return ResourceManager.GetString("NotSupportedStreamRead", resourceCulture);
            }
        }
    }
}
