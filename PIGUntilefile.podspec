#
#  Be sure to run `pod spec lint PIGUntilefile.podspec' to ensure this is a
#  valid spec and to remove all comments including this before submitting the spec.
#
#  To learn more about Podspec attributes see http://docs.cocoapods.org/specification.html
#  To see working Podspecs in the CocoaPods repo see https://github.com/CocoaPods/Specs/
#

Pod::Spec.new do |s|



  s.name         = "PIGUntilefile"
  s.version      = "1.6.0"
  s.summary      = "A short description of PIGUntilefile."

  s.description  = "工程 主要是 md5 sha1 sha256 eds RSA 5种加密算法 修改某些兼容性的BUG"
  s.homepage     = "https://github.com/PIGZHOUMINENG/PIGUntilefile"
 
  s.license      = "MIT"

  s.author       = { "PIGLANG" => "13608178525@163.com" }
  
  s.platform     = :ios,"8.0"

  s.source       = { :git => "https://github.com/PIGZHOUMINENG/PIGUntilefile.git", :tag => "#{s.version}" }


  s.source_files  = "PIGUntilefile/*.{h,m}"



  s.requires_arc = true

end
