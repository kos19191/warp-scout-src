# BouncyCastle отрабатывает по имени класса — не вырезать и не переименовывать.
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**
-dontwarn javax.naming.**
-dontwarn java.awt.**
