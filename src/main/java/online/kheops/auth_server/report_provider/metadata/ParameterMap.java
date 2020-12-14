package online.kheops.auth_server.report_provider.metadata;

import javax.json.JsonValue;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public interface ParameterMap extends OidcMetadata {
  <T> void put(Parameter<? super T> parameter, T value);

  default void putAll(ParameterMap parameterMap) {
    for (ParameterMap.Entry<?> entry: parameterMap.entrySet()) {
      putEntry(entry);
    }
  }

  default <T> void putEntry(ParameterMap.Entry<T> entry) {
    put(entry.getKey(), entry.getValue());
  }

  <T> T get(Parameter<? extends T> parameter);

  Set<Parameter<?>> keySet();

  Collection<?> values();

  Set<Entry<?>> entrySet();

  boolean containsKey(Parameter<?> parameter);

  boolean containsValue(Object value);

  int size();

  boolean isEmpty();

  boolean equals(Object var1);

  int hashCode();

  default <T> T getValue(Parameter<? extends T> parameter) {
    final T value = get(parameter);
    if (value != null) {
      return value;
    } else {
      return parameter.getEmptyValue();
    }
  }

  default  <T> T getValue(Parameter<? extends T> parameter, List<Locale.LanguageRange> priorityList) {
    return getValue(parameter);
  }

  default <T, S extends T, U extends S> T getOrDefault(Parameter<S> parameter, U defaultValue) {
    T v;
    return (v = this.get(parameter)) == null && !this.containsKey(parameter) ? defaultValue : v;
  }

  default <T> T getOrEmptyValue(Parameter<? extends T> parameter) {
    T v;
    return (v = this.get(parameter)) == null && !this.containsKey(parameter)
        ? parameter.getEmptyValue()
        : v;
  }

  static <T> Entry<T> entry(Parameter<? super T> parameter, T value) {
    return new ParameterValueHolder<>(parameter, value);
  }

  interface Entry<T> {
    Parameter<? super T> getKey();

    JsonValue jsonValue();

    T getValue();

    boolean equals(Object var1);

    int hashCode();
  }
 }
