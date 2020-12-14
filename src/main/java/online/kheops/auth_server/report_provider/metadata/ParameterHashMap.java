package online.kheops.auth_server.report_provider.metadata;

import java.util.*;

public class ParameterHashMap implements ParameterMap {
  private final Map<Parameter<?>, Object> map = new HashMap<>();

  @Override
  public <T> void put(Parameter<? super T> parameter, T value) {
    // cast to make sure that a ClassCastException is thrown
    // if the value is of the wrong type.
    map.put(parameter, parameter.cast(value));
  }

  @Override
  @SuppressWarnings("unchecked")
  public <T> T get(Parameter<? extends T> parameter) {
    return (T) map.get(parameter);
  }

  @Override
  public Set<Parameter<?>> keySet() {
    return map.keySet();
  }

  @Override
  public Collection<?> values() {
    return map.values();
  }

  @Override
  public Set<Entry<?>> entrySet() {
    final Set<Entry<?>> entries = new HashSet<>();
    for (Map.Entry<Parameter<?>, Object> entry: map.entrySet()) {
      @SuppressWarnings("unchecked")
      final Map.Entry<Parameter<? super Object>, Object> genericEntry
          = (Map.Entry<Parameter<? super Object>, Object>) entry;
      entries.add(ParameterMap.entry(genericEntry.getKey(), genericEntry.getValue()));
    }
    return entries;
  }

  @Override
  public boolean containsKey(Parameter<?> parameter) {
    return map.containsKey(parameter);
  }

  @Override
  public boolean containsValue(Object value) {
    return map.containsValue(value);
  }

  @Override
  public int size() {
    return map.size();
  }

  @Override
  public boolean isEmpty() {
    return map.isEmpty();
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj instanceof ParameterMap) {
      return entrySet().equals(((ParameterMap) obj).entrySet());
    }
    return false;
  }

  @Override
  public int hashCode() {
    return map.hashCode();
  }
}
