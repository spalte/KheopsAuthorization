package online.kheops.auth_server.report_provider.metadata;

import javax.json.JsonValue;
import online.kheops.auth_server.report_provider.metadata.ParameterMap.Entry;

final class ParameterValueHolder<T> implements Entry<T> {
  private final Parameter<? super T> key;
  private final T value;

  ParameterValueHolder(Parameter<? super T> key, T value) {
    this.key = key;
    this.value = value;
  }

  @Override
  public Parameter<? super T> getKey() {
    return key;
  }

  @Override
  public JsonValue jsonValue() {
    return key.jsonFrom(value);

  }

  public T getValue() {
    return value;
  }

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof ParameterMap.Entry)) {
      return false;
    } else {
      ParameterMap.Entry<?> e = (ParameterMap.Entry<?>)o;
      return this.key.equals(e.getKey()) && this.value.equals(e.getValue());
    }
  }

  @Override
  public int hashCode() {
    return this.key.hashCode() ^ this.value.hashCode();
  }

  @Override
  public String toString() {
    return this.key + "=" + this.value;
  }
}
