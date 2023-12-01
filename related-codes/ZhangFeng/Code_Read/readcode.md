# 后量子轨迹查找
1.重新定义了新的命名空间
![Alt text](image.png)

1.OQSKeyExchange()类的位置
related-codes\ZhangFeng\PQTLS1_3-master\fizz\crypto\exchange\OQSKeyExchange.h
2.AKCNKeyExchange()类的位置
related-codes\ZhangFeng\PQTLS1_3-master\fizz\crypto\exchange\AKCNKeyExchange.h
3.HybridKeyExchange的位置
related-codes\ZhangFeng\PQTLS1_3-master\fizz\crypto\exchange\HybridKeyExchange.h


## C++相关使用函数记录
### make_unique
在C++中，std::make_unique是一个用于创建动态分配的std::unique_ptr对象的函数模板。std::unique_ptr是C++11引入的智能指针，用于管理动态分配的对象生命周期，避免内存泄漏和手动释放的问题。

std::make_unique的作用是通过参数传递给构造函数来创建一个新的对象，并返回一个std::unique_ptr，这个指针拥有该对象的唯一所有权。使用std::make_unique相比直接使用new操作符或std::unique_ptr的构造函数更加安全和便捷，因为它可以避免内存泄漏，同时也可以提高代码的可读性。

以下是一个简单的示例，演示了使用std::make_unique的情况：
#include <memory>

class MyClass {
public:
    MyClass(int value) : value_(value) {
        // 构造函数的实现
    }

    void someFunction() {
        // 类的成员函数实现
    }

private:
    int value_;
};

int main() {
    // 使用 std::make_unique 创建 std::unique_ptr
    std::unique_ptr<MyClass> myObject = std::make_unique<MyClass>(42);

    // 使用 std::unique_ptr 操作对象
    myObject->someFunction();

    // 不需要手动释放内存，当 myObject 超出作用域时，会自动释放对象
    return 0;
}
### 类模板
在C++中，你可以使用模板来创建模板类（class template），并通过继承来派生自类模板。下面是一个简单的示例，演示了如何继承类模板：
```cpp
#include <iostream>

// 基类模板
template <typename T>
class BaseTemplate {
public:
    BaseTemplate(T value) : data_(value) {}

    void display() {
        std::cout << "BaseTemplate: " << data_ << std::endl;
    }

protected:
    T data_;
};

// 派生类模板
template <typename T>
class DerivedTemplate : public BaseTemplate<T> {
public:
    DerivedTemplate(T value, T additionalValue) : BaseTemplate<T>(value), additionalData_(additionalValue) {}

    void displayDerived() {
        // 可以访问基类的 protected 成员
        std::cout << "DerivedTemplate: " << this->data_ << ", Additional: " << additionalData_ << std::endl;
    }

private:
    T additionalData_;
};

int main() {
    // 使用类模板
    DerivedTemplate<int> derivedObject(42, 10);

    // 调用基类模板的成员函数
    derivedObject.display();

    // 调用派生类模板的成员函数
    derivedObject.displayDerived();

    return 0;
}
```
在这个例子中，BaseTemplate是一个模板类，它有一个模板参数 T。DerivedTemplate 类通过 : public BaseTemplate<T> 表示它继承自 BaseTemplate。通过这种方式，DerivedTemplate 可以访问 BaseTemplate 中的成员变量和成员函数。

需要注意的是，由于模板的特殊性，对于继承类模板，需要在继承时显式提供模板参数。在 main 函数中，我们创建了一个 DerivedTemplate<int> 类的对象，并调用了基类和派生类的成员函数。

这里要注意的是，在派生类中，为了访问基类的成员变量 data_，我们使用了 this->data_ 或者直接 BaseTemplate<T>::data_，因为在模板中，名称查找可能会更加复杂。