/**
 * caches the result of a getter on first access
 */
export function cache<T, K>(originalMethod: (this: T) => K, context: ClassGetterDecoratorContext) {
	return function (this: T): K {
		const value = originalMethod.call(this);

		Object.defineProperty(this, context.name, { value, writable: false, enumerable: false });
		return value;
	};
}
