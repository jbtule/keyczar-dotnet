using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Text;

namespace Keyczar.Util
{
    /// <summary>
    /// Read only array helper
    /// </summary>
    public static class ReadOnlyArray
    {
        /// <summary>
        /// Creates the specified ReadOnlyArray with items.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="items">The items.</param>
        /// <returns></returns>
        public static ReadOnlyArray<T> Create<T>(params T[] items)
        {
            return new ReadOnlyArray<T>(items);
        }
    }

    /// <summary>
    /// A read only array like object
    /// </summary>
    /// <typeparam name="T"></typeparam>
    [ImmutableObject(true)]
    public class ReadOnlyArray<T> : ReadOnlyCollection<T>
    {
        /// <summary>
        /// Ts the specified array.
        /// </summary>
        /// <param name="array">The array.</param>
        /// <returns></returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage",
            "CA2225:OperatorOverloadsHaveNamedAlternates", Justification = "Linq Provides the alternative")]
        public static implicit operator T[](ReadOnlyArray<T> array)
        {
            return array.ToArray();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="ReadOnlyArray" /> class.
        /// </summary>
        /// <param name="items">The items.</param>
        public ReadOnlyArray(params T[] items)
            : base(items)
        {
        }

        /// <summary>
        /// Gets the length. Convience to match up with Array interface, but just calls Count
        /// </summary>
        /// <value>
        /// The length.
        /// </value>
        public int Length
        {
            get { return Count; }
        }
    }
}